import os
from collections import defaultdict
import asyncio
import pickle
import json
from okta.client import Client as OktaClient
import schemdraw
from schemdraw import flow


def read_credentails(service):
    credentails = {}
    credentails_file = f"{service}.creds"
    if not os.path.exists(credentails_file):
        print("Unable to open {service} credentails")
    with open(credentails_file, 'r') as creds_fp:
        credentails = json.load(creds_fp)
    return credentails


async def fetch_groups(okta_client):
    query_parameters = {'limit': 500}
    output_groups, resp, err = await okta_client.list_groups(query_parameters)
    while resp.has_next():
        groups, err = await resp.next()
        output_groups += groups
        print(f"Loaded {len(groups)} groups")
    return output_groups


async def get_okta_groups_coroutine(okta_client):
    all_users = []
    okta_users_file = "okta_groups.pickle"
    if os.path.exists(okta_users_file):
        groups = pickle.load(open(okta_users_file, "rb"))
    else:
        groups = await(fetch_groups(okta_client))
        pickle.dump(groups, open(okta_users_file, "wb"))
    output_groups = {}
    for group in groups:
        output_groups[group.id] = group
    return output_groups


async def get_okta_networks_coroutine(okta_client):
    output_networks = {}
    okta_networks_file = "okta_networks.pickle"
    if os.path.exists(okta_networks_file):
        networks = pickle.load(open(okta_networks_file, "rb"))
    else:
        networks, resp, err = await okta_client.list_network_zones()
        pickle.dump(networks, open(okta_networks_file, "wb"))
    for network in networks:
        output_networks[network.id] = network
    return output_networks

async def get_okta_users_coroutine(okta_client):
    output_users = {}
    okta_users_file = "okta_users.pickle"
    if os.path.exists(okta_users_file):
        users = pickle.load(open(okta_users_file, "rb"))
    else:
        users, resp, err = await okta_client.list_users()
        pickle.dump(users, open(okta_users_file, "wb"))
    for user in users:
        output_users[user.id] = user
    return output_users

async def get_okta_user_types_coroutine(okta_client):
    output_user_types = {}
    okta_user_types_file = "okta_user_types.pickle"
    if os.path.exists(okta_user_types_file):
        user_types = pickle.load(open(okta_user_types_file, "rb"))
    else:
        user_types, resp, err = await okta_client.list_user_types()
        pickle.dump(user_types, open(okta_user_types_file, "wb"))
    for user_type in user_types:
        output_user_types[user_type.id] = user_type
    return output_user_types

def get_okta_apps():
    # Eventually this will work
    #apps = await okta_client.list_applications({"filter": f"name eq \"oidc_client\""})
    import requests
    apps_by_id = {}
    config = read_credentails("okta")
    headers = {
        "Content-Type": "application/json",
        "Accept":"application/json",
        "Authorization": f"SSWS {config['token']}"
    }
    resp = requests.get(f"{config['orgUrl']}/api/v1/apps", headers=headers)
    for app in resp.json():
        apps_by_id[app['id']] = app
    return apps_by_id

async def get_okta_policies(okta_client, type):
    output_policies = {}
    okta_policy_file = f"okta_{type.lower()}.pickle"
    if os.path.exists(okta_policy_file):
        output_policies = pickle.load(open(okta_policy_file, "rb"))
    else:
        policies, resp, err = await okta_client.list_policies({"type": type})
        for policy in policies:
            rules, resp, err = await okta_client.list_policy_rules(policy.id)
            policy_id = policy.id
            output_policies[policy_id] = {"Policy": policy, "Rules": rules}
        pickle.dump(output_policies, open(okta_policy_file, "wb"))
    return output_policies

def get_okta_handler():
    config = read_credentails("okta")
    okta_client = OktaClient(config)
    return okta_client

def label_format(label):
    out = ""
    start = 0
    for i in range(0, len(label), 25):
        out += label[start:i] + "-\n"
        start = i
    out += label[start:len(label)]
    return out

async def extract_access_rule_conditions(policy_rule, okta_client, skip_defaults=False):
    # With access policies every Auth policy has one rule that is default
    if policy_rule.system:
        return [flow.Decision(w=5.5, h=4, E='YES', S='NO').label(label_format(f"Is valid Okta user"))]

    networks = await get_okta_networks_coroutine(okta_client)
    user_types = await get_okta_user_types_coroutine(okta_client)
    groups = await get_okta_groups_coroutine(okta_client)
    users = await get_okta_users_coroutine(okta_client)

    conditions = []
    if policy_rule.conditions.user_type and policy_rule.conditions.user_type.include:
        user_types_access = policy_rule.conditions.user_type.include
        type_names = [user_types[type_id].name for type_id in user_types_access]
        policy_rule_condition = flow.Decision(w=5.5, h=4, N='', E='YES', S='NO').label(label_format(f"Is user type is {' or '.join(type_names)}"))
    if policy_rule.conditions.user_type.exclude:
        user_types_access = policy_rule.conditions.user_type.exclude
        type_names = [user_types[type_id].name for type_id in user_types_access]
        policy_rule_condition = flow.Decision(w=5.5, h=4, N='', E='YES', S='NO').label(label_format(f"Is user type is NOT {' or '.join(type_names)}"))
        conditions.append(policy_rule_condition)
    # User Group
    if policy_rule.conditions.people.groups:
        if policy_rule.conditions.people.groups.include:
            group_access = policy_rule.conditions.people.groups.include
            group_names = [groups[group_id].profile.name for group_id in group_access]
            policy_rule_condition = flow.Decision(w=5.5, h=4, N='', E='YES', S='NO').label(label_format(f"Is user in group {' or '.join(group_names)}"))
            conditions.append(policy_rule_condition)
        if policy_rule.conditions.people.groups.exclude:
            group_access = policy_rule.conditions.people.groups.exclude
            group_names = [groups[group_id].profile.name for group_id in group_access]
            policy_rule_condition = flow.Decision(w=5.5, h=4, N='', E='YES', S='NO').label(label_format(f"Is user in NOT group {' or '.join(group_names)}"))
            conditions.append(policy_rule_condition)
    # User Name
    if policy_rule.conditions.people.users:
        if policy_rule.conditions.people.users.include:
            user_access = policy_rule.conditions.people.users.include
            user_names = [users[user_id].profile.login for user_id in user_access]
            policy_rule_condition = flow.Decision(w=5.5, h=4, N='', E='YES', S='NO').label(label_format(f"Is username {' or '.join(user_names)}"))
            conditions.append(policy_rule_condition)
        if policy_rule.conditions.people.users.exclude:
            user_access = policy_rule.conditions.people.users.exclude
            user_names = [users[user_id].profile.login for user_id in user_access]
            policy_rule_condition = flow.Decision(w=5.5, h=4, N='', E='YES', S='NO').label(label_format(f"Is username NOT {' or '.join(user_names)}"))
            conditions.append(policy_rule_condition)
    # Device State
    if policy_rule.conditions.device:
        if policy_rule.conditions.device.registered:
            policy_rule_condition = flow.Decision(w=5.5, h=4, N='', E='YES', S='NO').label(label_format(f"Is user device registered"))
            conditions.append(policy_rule_condition)
        # Device Mgmt
        if policy_rule.conditions.device.managed:
            policy_rule_condition = flow.Decision(w=5.5, h=4, N='', E='YES', S='NO').label(label_format(f"Is user device managed"))
            conditions.append(policy_rule_condition)
    # Device Assurance
    # ???
    # Device Platform
    if policy_rule.conditions.platform and policy_rule.conditions.platform.include:
        platforms = policy_rule.conditions.platform.include
        platform_names = [platform.os.type for platform in policy_rule.conditions.platform.include]
        policy_rule_condition = flow.Decision(w=5.5, h=4, N='', E='YES', S='NO').label(label_format(f"Is user device running {' or '.join(platform_names)}"))
        conditions.append(policy_rule_condition)
    # Network
    if policy_rule.conditions.network.exclude:
        network_zones = policy_rule.conditions.network.exclude
        if network_zones == ["ALL_ZONES"]:
            policy_rule_condition = flow.Decision(w=5.5, h=4, N='', E='YES', S='NO').label(label_format(f"Is user NOT in Any Zone"))
        else:
            network_names = [networks[network_id].name for network_id in network_zones]
            policy_rule_condition = flow.Decision(w=5.5, h=4, N='', E='YES', S='NO').label(label_format(f"Is user NOT in Network Range {' or '.join(network_names)}"))
        conditions.append(policy_rule_condition)
    if policy_rule.conditions.network.include:
        network_zones = policy_rule.conditions.network.include
        if network_zones == ["ALL_ZONES"]:
            policy_rule_condition = flow.Decision(w=5.5, h=4, N='', E='YES', S='NO').label(label_format(f"Is user in Any Zone"))
        else:
            network_names = [networks[network_id].name for network_id in network_zones]
            policy_rule_condition = flow.Decision(w=5.5, h=4, N='', E='YES', S='NO').label(label_format(f"Is user in Network Range {' or '.join(network_names)}"))
        conditions.append(policy_rule_condition)
    # Risk
    if policy_rule.conditions.risk_score and policy_rule.conditions.risk_score.level:
        risk_level = policy_rule.conditions.risk_score.level
        policy_rule_condition = flow.Decision(w=5.5, h=4, N='', E='YES', S='NO').label(label_format(f"Is Risk Score {risk_level}"))
        if risk_level == "ANY" and skip_defaults:
            pass
        else:
            conditions.append(policy_rule_condition)
    # Custom Expression
    if policy_rule.conditions.el_condition and policy_rule.conditions.el_condition.condition:
        policy_rule_condition = flow.Decision(w=5.5, h=4, N='', E='YES', S='NO').label(label_format(f"Does user pass custom expression?"))
        conditions.append(policy_rule_condition)
    return conditions

def get_apps_by_auth_policy(apps):
    auth_policies = defaultdict(lambda: [])
    for app_id, app in apps.items():
        if 'accessPolicy' in app['_links']:
            access_policy_id = app['_links']['accessPolicy']['href'].rsplit('/', 1)[-1]
            auth_policies[access_policy_id].append(app_id)
        else:
            print(f"Skipping {app['name']} as it doesn't have an access policy")
    return auth_policies

async def make_policies(d, authentication_policies, okta_client):
    default_skip = True
    policy_conditions = {}
    rule_conditions = defaultdict(lambda: [])
    apps_by_id = get_okta_apps()

    apps_by_policy = get_apps_by_auth_policy(apps_by_id)
    # Generate possible app logins
    for policy_id, app_ids in apps_by_policy.items():
        apps_by_name = [apps_by_id[app_id]['name'] for app_id in app_ids]
        current_policy = authentication_policies[policy_id]
        policy_name = current_policy['Policy'].name
        # We actually need to specify the length for the policy BEFORE because
        # this is the distance to the current policy
        all_policies = list(apps_by_policy.keys())
        previous_policy_index = all_policies.index(policy_id)-1
        if previous_policy_index == -1:
            number_of_units = d.unit
        else:
            previous_policy_id = all_policies[previous_policy_index]
            previous_policy = authentication_policies[previous_policy_id]
            # Each line is d.unit/2 length and there will be n of them
            line_length = d.unit/2 * (len(previous_policy['Rules']))
            # each decision is 4 and there N of them + the access denied
            object_length = 4 * len(previous_policy['Rules']) + 1
            number_of_units = (line_length + object_length)
        d.add(flow.Arrow().down(number_of_units))
        policy_condition = flow.Decision(w=5.5, h=4, E='YES', S='NO').label(label_format(f"Is the user accessing: {', '.join(apps_by_name)}"))
        policy_conditions[policy_id] = d.add(policy_condition)
    # Generate First Rule Nodes
    for policy_id, app_ids in apps_by_policy.items():
        policy_struct = authentication_policies[policy_id]
        print(policy_struct['Policy'].name)
        policy_object = policy_conditions[policy_id]
        # If we're at the end of a rule, we'll next to direct to the next policy
        all_policies = list(apps_by_policy.keys())
        next_policy_index = all_policies.index(policy_id)+1
        if next_policy_index < len(apps_by_policy):
            next_policy_id = list(apps_by_policy)[next_policy_index]
            next_policy_object = policy_conditions[next_policy_id]
        else:
            next_policy_id = None
            next_policy_object = None
        for row_depth, policy_rule in enumerate(policy_struct['Rules']):
            # If this is the first row, move out from the policy object
            if row_depth == 0:
                d.add(flow.Arrow().right(d.unit/2).at(policy_object.E))
            # If its not the first row, make a down arrow to the previous row
            else:
                d.add(flow.Arrow().down(d.unit/2).at(first_row_condition.S))
            conditions = await extract_access_rule_conditions(policy_rule, okta_client, skip_defaults=default_skip)
            # We don't need to catch empty conditions cause there is always a default catch-all
            # At the end there is a Default Allow, we make it more readable
            if policy_rule.system == True:
                first_row_condition = d.add(flow.Decision(w=5.5, h=4, E='YES', S='NO').label("Is the user valid in Okta?"))
            else:
                first_row_condition = d.add(conditions[0])
            rule_conditions[policy_rule.id] = [first_row_condition]
            print(f"\t{policy_rule.id} - {policy_rule.name}")
        # Make all the rest of the rules
        for row_depth, policy_rule in enumerate(policy_struct['Rules']):
            # There is another rule and failures go to it
            if row_depth+1 < len(policy_struct['Rules']):
                next_row_policy_id = policy_struct['Rules'][row_depth+1].id
                next_row_object = rule_conditions[next_row_policy_id]
            # There isn't another rule so failures go to next policy
            else:
                policy_conditions[policy_id]
                next_row_object = None
            most_recent_rule = rule_conditions[policy_rule.id][0]
            conditions = await extract_access_rule_conditions(policy_rule, okta_client, skip_defaults=default_skip)

            # If there are no conditions (all conditions are default) then draw a line from our 'default' box
            if not conditions:
                # Push each rule option to the next policy
                if not next_row_object and next_policy_object:
                    first_rule_object = rule_conditions[policy_rule.id][0]
            else:
                for condition_index, condition in enumerate(conditions):
                    # We have already created these first indexes so we skip
                    # but we still wanna create the line
                    if condition_index != 0:
                        d.add(flow.Arrow().right(d.unit/2).at(most_recent_rule.E))
                        most_recent_rule = d.add(condition)
                    # If there is another rule, we need to set failure conditions to go to it
                    if next_row_object:
                        d.add(flow.Wire('-', arrow='->').at(most_recent_rule.S).to(next_row_object[0].N))
                    # If there is not another rule, then we need to set failure conditions to go to the next policy
                    else:
                        if next_policy_object:
                            # push the first rule to the next policy, we'll end up redrawing this a few times
                            first_rule_object = rule_conditions[policy_rule.id][0]
                            d.add(flow.Arrow().down(d.unit/2).at(first_rule_object.S))
                            d.add(flow.Box(w=3.5, h=4).label('Access is denied.'))
            d.add(flow.Arrow().right(d.unit/2).at(most_recent_rule.E))
            if policy_rule.actions.app_sign_on.access == "ALLOW":
                d.add(flow.Box(w=3.5, h=4).label('Access is Allowed.'))
            else:
                d.add(flow.Box(w=3.5, h=4).label('Access is denied.'))

def main():
    okta_client = get_okta_handler()
    authentication_policies = asyncio.run(get_okta_policies(okta_client, "ACCESS_POLICY"))
    d = schemdraw.Drawing()
    start = flow.Start().label('Start Login')
    d.add(start)
    asyncio.run(make_policies(d, authentication_policies, okta_client))
    d.save('auth-flowchart.svg')

if __name__ == "__main__":
    main()
