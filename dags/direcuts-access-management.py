# dags/update_directus_policies.py

import fnmatch, json, logging, requests
from datetime import datetime

import yaml
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.providers.http.hooks.http import HttpHook
from airflow.models import Variable

# CONFIG

CONFIG_PATH = "/usr/local/airflow/include/directus_access_policy/access_policy.yaml"
# HELPERS


def load_config_file():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _hook(method="GET"):
    return HttpHook(method=method, http_conn_id="api-directus")


def _run(method, endpoint, data=None):
    
    if endpoint =="/roles?limit=-1":
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {Variable.get('directus-api-token')}",
            "Content-Type": "application/json"
        }

        response = requests.get(Variable.get('directus-api-url') + endpoint, headers=headers)
        response.raise_for_status()
        print('response',response.json())
        return response.json()
    
    else:
        hook = _hook(method)
        payload = None
        if data is not None:
            payload = json.loads(json.dumps(data))
        resp = hook.run(endpoint, json=payload, extra_options={"check_response": True})
        
        if method.upper() == "DELETE" or resp.status_code == 204:
            return {"status": resp.status_code}

        try:
            return resp.json()
        except ValueError:  # response body isn’t valid JSON
            logging.error(
                f"Invalid JSON response for {endpoint}, status {resp.status_code}"
            )
            return {}


def normalize_fields(val):
    if not val:
        return []
    if isinstance(val, str):
        try:
            return json.loads(val)
        except json.JSONDecodeError:
            return [val]
    if isinstance(val, list):
        return val
    return [val]


def expand_fields(all_fields, collection, requested, ro_global, write_excl):
    fields = [f["field"] for f in all_fields if f.get("collection") == collection]
    if not requested or requested == ["*"]:
        out = [
            f
            for f in fields
            if f not in ro_global and f not in write_excl.get(collection, [])
        ]
    elif any(f.startswith("!") for f in requested):
        out = [
            f
            for f in fields
            if f not in {x[1:] for x in requested if x.startswith("!")}
        ]
    else:
        out = requested
    return sorted(set(out))


# TASKS


def export_current_state():
    cfg = load_config_file()
    collections = _run("GET", "/collections?limit=-1").get("data", [])
    fields = _run("GET", "/fields?limit=-1").get("data", [])
    policies = _run("GET", "/policies?limit=-1").get("data", [])
    perms = _run("GET", "/permissions?limit=-1").get("data", [])
    roles = _run("GET", "/roles?limit=-1").get("data", [])

    logging.info(
        f"[EXPORT] {len(collections)} cols, {len(fields)} fields, "
        f"{len(policies)} policies, {len(perms)} perms, {len(roles)} roles"
    )

    return {
        "collections": [c["collection"] for c in collections if c.get("collection")],
        "fields": fields,
        "policies": policies,
        "permissions": perms,
        "roles": roles,
        "cfg": cfg,
    }


def compile_desired_state(state=None, **ctx):

    if state is None:
        state = export_current_state()

    cfg = state["cfg"]
    all_cols = state["collections"]
    fields = state["fields"]

    defaults = cfg.get("defaults", {})
    policies_raw = cfg.get("policies", [])
    ro_global = set(defaults.get("readonly_fields", []))
    write_excl = defaults.get("write_field_excludes", {})
    directus_common = defaults.get("directus_common", {})

    desired = []

    for p in policies_raw:
        name = p["name"]
        desc = p.get("description", "")
        roles = p.get("roles", [])

        explicit_perms = set()
        desired_perms = []

        collections_rules = p.get("rules", {}).get("collections", {})

        # Add directus_common rules to collections_rules for this policy
        all_collection_rules = dict(directus_common)
        all_collection_rules.update(collections_rules)

        for col, rule in all_collection_rules.items():
            # Support wildcard collection names
            if "*" in col:
                matched_cols = [c for c in all_cols if fnmatch.fnmatch(c, col)]
            else:
                matched_cols = [col] if col in all_cols else []

            if not matched_cols:
                logging.warning(
                    f"No collections matched pattern '{col}' in policy '{name}'"
                )
                continue

            actions = set(rule.get("actions", [])) | set(
                (rule.get("permissions") or {}).keys()
            )

            for matched_col in matched_cols:
                for act in actions:
                    explicit_perms.add((matched_col, act))

                    fset = expand_fields(
                        fields,
                        matched_col,
                        rule.get("fields", {}).get(act, ["*"]),
                        ro_global,
                        write_excl,
                    )
                    perm_obj = {
                        "collection": matched_col,
                        "action": act,
                        "fields": fset,
                    }

                    # Special permission rules
                    if "permissions" in rule:
                        perms_for_action = (rule.get("permissions") or {}).get(act)
                        if perms_for_action:
                            logging.info(
                                f"Adding special permissions for {name}.{matched_col}.{act}"
                            )
                            perm_obj["permissions"] = perms_for_action

                    desired_perms.append(perm_obj)

        if p.get("rules", {}).get("read_all", False):
            exclude_collections = defaults.get("exclude_collections", [])

            for col in all_cols:
                if any(col.startswith(ex) or col == ex for ex in exclude_collections):
                    continue

                if (col, "read") in explicit_perms:
                    logging.debug(
                        f"Skipping read_all for {col} - has explicit read permission"
                    )
                    continue

                desired_perms.append(
                    {"collection": col, "action": "read", "fields": ["*"]}
                )

        # Broad CRUD permissions
        broad = p.get("rules", {}).get("__broad_crud__", {})
        if broad.get("write_to_all_non_excluded", False):
            write_actions = broad.get("write_actions", ["create", "update", "delete"])
            policy_excl = p.get("rules", {}).get("exclude_collections", [])
            all_exclusions = defaults.get("exclude_collections", []) + policy_excl

            for col in all_cols:
                if any(fnmatch.fnmatch(col, ex) for ex in all_exclusions):
                    continue

                for act in write_actions:
                    if (col, act) in explicit_perms:
                        logging.debug(
                            f"Skipping broad CRUD for {col}.{act} - has explicit permission"
                        )
                        continue

                    fset = expand_fields(
                        fields,
                        col,
                        broad.get("fields", {}).get(act, ["*"]),
                        ro_global,
                        write_excl,
                    )
                    perm_obj = {"collection": col, "action": act, "fields": fset}
                    desired_perms.append(perm_obj)

        seen = set()
        unique_perms = []
        for perm in desired_perms:
            key = (perm["collection"], perm["action"])
            if key not in seen:
                seen.add(key)
                unique_perms.append(perm)
            else:
                for i, existing in enumerate(unique_perms):
                    if (existing["collection"], existing["action"]) == key:
                        if perm.get("permissions") and not existing.get("permissions"):
                            unique_perms[i] = perm
                        break

        desired.append(
            {"policy": name, "description": desc, "roles": roles, "perms": unique_perms}
        )

    logging.info(f"[COMPILE] Successfully compiled {len(desired)} desired policies")
    return desired


def diff_and_apply():
    state = export_current_state()
    desired = compile_desired_state(state=state)
    existing_policies = {p["name"]: p for p in state["policies"]}
    existing_roles = {r["name"]: r for r in state["roles"]}
    existing_perms = {
        (e["policy"], e["collection"], e["action"]): e for e in state["permissions"]
    }

    for pol in desired:
        name, desc, roles, perms = (
            pol["policy"],
            pol["description"],
            pol["roles"],
            pol["perms"],
        )
        resp = _run("GET", f"/policies?filter[name][_eq]={name}")
        data = resp.get("data", [])
        policy_id = data[0].get("id") if data else None
        roles_payload = [
            {"role": existing_roles[r]["id"]} for r in roles if r in existing_roles
        ]

        # --- Create or update policy ---
        if name not in existing_policies:
            logging.info(f"[DIFF] creating policy {name}")
            created = _run(
                "POST",
                "/policies",
                {"name": name, "description": desc, "roles": roles_payload},
            )
            policy_id = (created.get("data") or {}).get("id")
        else:
            policy_id = existing_policies[name]["id"]
            logging.info(f"[DIFF] patching policy {name}")
            _run(
                "PATCH",
                f"/policies/{policy_id}",
                {"description": desc, "roles": roles_payload},
            )

        # --- Delete Permissions not in desired state ---
        if policy_id:
            current_policy_perms = [
                p for p in state["permissions"] if p["policy"] == policy_id
            ]
            to_be_deleted_perms = [
                p["id"]
                for p in current_policy_perms
                if (p["collection"], p["action"])
                not in {(perm["collection"], perm["action"]) for perm in pol["perms"]}
            ]

            _run("DELETE", "/permissions", to_be_deleted_perms)

        # --- Apply permissions ---
        for perm in perms:
            key = (policy_id, perm["collection"], perm["action"])
            if key not in existing_perms:
                logging.info(f"[DIFF] adding perm {perm}")
                payload = dict(perm)
                payload["policy"] = policy_id
                _run("POST", "/permissions", payload)
            else:
                existing = existing_perms[key]
                current_fields = sorted(normalize_fields(existing.get("fields")))
                desired_fields = sorted(perm["fields"])
                desired_permissions = perm.get("permissions")

                if current_fields != desired_fields or desired_permissions is not None:
                    patch_payload = {"fields": desired_fields}
                    if desired_permissions is not None:
                        patch_payload["permissions"] = desired_permissions

                    logging.info(f"[DIFF] patching perm {perm}")
                    _run("PATCH", f"/permissions/{existing['id']}", patch_payload)

    logging.info(f"Done updating policies and permissions.")


# DAG

default_args = {"retries": 2}

with DAG(
    dag_id="directus_access_manager",
    start_date=datetime(2025, 9, 11),
    schedule="@daily",
    catchup=False,
    default_args=default_args,
    tags=["directus", "access", "policies"],
) as dag:

    export = PythonOperator(
        task_id="export_current_state", python_callable=export_current_state
    )
    compile = PythonOperator(
        task_id="compile_desired_state", python_callable=compile_desired_state
    )
    apply = PythonOperator(task_id="diff_and_apply", python_callable=diff_and_apply)

    export >> compile >> apply
