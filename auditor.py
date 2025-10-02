from collections import defaultdict
import re
import traceback
import yaml
import paramiko
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple, Literal
from datetime import datetime
import json
import os


def parse_device_inventory(filepath: str = "device_inventory.yaml") -> List[Dict]:
    """
    Parse the device inventory YAML file and return a list of device configurations.

    Args:
        filepath (str): Path to the device inventory YAML file

    Returns:
        List[Dict]: List of device dictionaries containing hostname, ip, username,
                   password, and description
    """
    try:
        with open(
            filepath, "r"
        ) as file:  # open the file safely, and return the devices
            inventory = yaml.safe_load(file)
            return inventory.get("devices", [])
    except FileNotFoundError:
        print(f"Error: Could not find {filepath}")
        return []
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file: {e}")
        return []


@dataclass
class ComplianceRule:
    """Data class representing an SSH compliance rule"""

    rule: str
    parameter: str
    expected: str
    severity: str


def parse_ssh_baseline(
    filepath: str = "baselines/ssh_baseline.yaml",
) -> Tuple[Dict[str, str], List[ComplianceRule]]:
    """
    Parse the SSH baseline YAML file and return the configuration and compliance rules.

    Args:
        filepath (str): Path to the SSH baseline YAML file

    Returns:
        Tuple[Dict[str, str], List[ComplianceRule]]: Tuple containing:
            - Dictionary of SSH baseline configuration
            - List of compliance rules as ComplianceRule objects
    """
    try:
        with open(filepath, "r") as file:
            baseline = yaml.safe_load(file)

            # Parse SSH config dictionary
            ssh_config = baseline.get("ssh_config", {})

            # Parse compliance rules into dataclass objects
            compliance_rules = [
                ComplianceRule(
                    rule=rule["rule"],
                    parameter=rule["parameter"],
                    expected=rule["expected"],
                    severity=rule["severity"],
                )
                for rule in baseline.get("compliance_rules", [])
            ]

            return ssh_config, compliance_rules

    except FileNotFoundError:
        print(f"Error: Could not find {filepath}")
        return {}, []
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file: {e}")
        return {}, []


@dataclass
class UserRule:
    """Data class representing a user account rule"""

    username: str
    description: str
    severity: str
    type: Literal["required", "prohibited"]


@dataclass
class PasswordPolicy:
    """Data class representing password policy settings"""

    max_days: int
    min_days: int
    warn_age: int


def parse_users_baseline(
    filepath: str = "baselines/users_baseline.yaml",
) -> Tuple[List[UserRule], PasswordPolicy]:
    """
    Parse the users baseline YAML file and return user rules and password policy.

    Args:
        filepath (str): Path to the users baseline YAML file

    Returns:
        Tuple[List[UserRule], PasswordPolicy]: Tuple containing:
            - List of user rules as UserRule objects
            - Password policy as PasswordPolicy object
    """
    try:
        with open(filepath, "r") as file:
            baseline = yaml.safe_load(file)

            # Parse required users
            required_users = [
                UserRule(
                    username=user["username"],
                    description=user["description"],
                    severity=user["severity"],
                    type="required",
                )
                for user in baseline.get("required_users", [])
            ]

            # Parse prohibited users
            prohibited_users = [
                UserRule(
                    username=user["username"],
                    description=user["description"],
                    severity=user["severity"],
                    type="prohibited",
                )
                for user in baseline.get("prohibited_users", [])
            ]

            # Parse password policy
            policy_data = baseline.get("password_policy", {})
            password_policy = PasswordPolicy(
                max_days=policy_data.get("max_days", 99999),
                min_days=policy_data.get("min_days", 0),
                warn_age=policy_data.get("warn_age", 7),
            )

            return required_users + prohibited_users, password_policy

    except FileNotFoundError:
        print(f"Error: Could not find {filepath}")
        return [], PasswordPolicy(99999, 0, 7)
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file: {e}")
        return [], PasswordPolicy(99999, 0, 7)


@dataclass
class FirewallRule:
    """Data class representing a firewall rule"""

    port: int
    protocol: str
    action: str
    description: str
    severity: str
    type: Literal["allowed", "blocked"]


@dataclass
class DefaultPolicy:
    """Data class representing default firewall policies"""

    INPUT: str
    FORWARD: str
    OUTPUT: str


def parse_firewall_baseline(
    filepath: str = "baselines/firewall_baseline.yaml",
) -> Tuple[List[FirewallRule], DefaultPolicy]:
    """
    Parse the firewall baseline YAML file and return rules and default policy.

    Args:
        filepath (str): Path to the firewall baseline YAML file

    Returns:
        Tuple[List[FirewallRule], DefaultPolicy]: Tuple containing:
            - List of firewall rules as FirewallRule objects
            - Default policy as DefaultPolicy object
    """
    try:
        with open(filepath, "r") as file:
            baseline = yaml.safe_load(file)

            # Parse required (allowed) rules
            allowed_rules = [
                FirewallRule(
                    port=rule["port"],
                    protocol=rule["protocol"],
                    action=rule["action"],
                    description=rule["description"],
                    severity=rule["severity"],
                    type="allowed",
                )
                for rule in baseline.get("required_rules", [])
            ]

            # Parse blocked rules
            blocked_rules = [
                FirewallRule(
                    port=rule["port"],
                    protocol=rule["protocol"],
                    action=rule["action"],
                    description=rule["description"],
                    severity=rule["severity"],
                    type="blocked",
                )
                for rule in baseline.get("blocked_rules", [])
            ]

            # Parse default policy
            policy_data = baseline.get("default_policy", {})
            default_policy = DefaultPolicy(
                INPUT=policy_data.get("INPUT", "DROP"),
                FORWARD=policy_data.get("FORWARD", "DROP"),
                OUTPUT=policy_data.get("OUTPUT", "ACCEPT"),
            )

            return allowed_rules + blocked_rules, default_policy

    except FileNotFoundError:
        print(f"Error: Could not find {filepath}")
        return [], DefaultPolicy("DROP", "DROP", "ACCEPT")
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file: {e}")
        return [], DefaultPolicy("DROP", "DROP", "ACCEPT")


def get_score(severity: str) -> int:
    """
    Return score deduction based on violation severity.

    Args:
        violation (str): Severity of the violation ("critical" or "warning")

    Returns:
        int: Score deduction
    """
    if severity.lower() == "critical":
        return 15
    elif severity.lower() == "warning":
        return 5
    return 0


def add_violation(
    violation_log: Dict[str, List[any]],
    device: str,
    violation: str,
    severity: str,
    expected: str,
    actual: str,
    recommendation: str = "",
):
    """
    Add a violation entry to the violation log.

    Args:
        violation_log (Dict[str, List[any]]): The violation log dictionary
        device (str): Device hostname
        violation (str): Description of the violation
        severity (str): Severity of the violation
        expected (str): Expected value
        actual (str): Actual value found
    """
    violation_entry = {
        "violation": violation,
        "device": device,
        "expected": expected,
        "actual": actual,
        "recommendation": recommendation,
    }
    violation_log[severity].append(violation_entry)


def audit_all_devices():
    """
    Connect to all devices in inventory and retrieve their configurations.
    """
    # Read all baseline configurations
    ssh_config_baseline, ssh_compliance_rules = parse_ssh_baseline()
    user_rules, password_policy = parse_users_baseline()
    firewall_rules, default_policy = parse_firewall_baseline()
    devices = parse_device_inventory()

    violation_log = defaultdict(list)

    for device in devices:
        print(f"\nAuditing {device['hostname']} ({device['ip']})...")

        # scores initialization. will add a score for each machine, defaults to zero.
        # critical violations: -15 points
        # warning violation: -5 points

        # User compliance check
        print("\nUser Account Check:")
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            password = device.get("password")
            ssh_client.connect(
                device["ip"],
                username=device["username"],
                password=device["password"],
                timeout=10,
            )
            user_score = get_user_violations(
                user_rules, password_policy, ssh_client, violation_log, device
            )

            ssh_score = get_ssh_violations(
                ssh_client, password, ssh_config_baseline, ssh_compliance_rules, violation_log, device
            )

            # Add firewall compliance check
            print("\nFirewall Rules Check:")
            firewall_score = get_firewall_violations(
                firewall_rules, default_policy, violation_log, device, ssh_client, password
            )
            total_score = max(100 - (ssh_score + user_score + firewall_score),0)
            print(
                f"\nTotal Compliance Score for {device['hostname']}: {total_score}/100"
            )
            violation_log["summary"].append(
                {
                    "device": device["hostname"],
                    "ssh_score": -ssh_score,
                    "user_score": -user_score,
                    "firewall_score": -firewall_score,
                    "total_score": total_score,
                }
            )

        except Exception as e:
            print(f"  [ERROR] Could not connect to device {device['ip']}: {str(e)}")
        finally:
            ssh_client.close()
    return violation_log


def get_firewall_violations(
    firewall_rules, default_policy, violation_log, device, ssh_client, password
):
    current_score = 0
    try:
        # Get iptables rules
        stdin, stdout, _ = ssh_client.exec_command("sudo iptables -L -n", get_pty=True)
        stdin.write(f"{password}\n")
        stdin.flush()

        iptables_output = stdout.read().decode()

        # Get default policies
        # i dont think i understand the zero packets, zero bytes. are we not pulling out the right information?
        # if accepting nothing is the same as dropping it, then why is our output policy not anything either?
        chain_policies = {}
        current_chain = None
        for line in iptables_output.splitlines():
            if line.startswith("Chain"):
                current_chain = line.split()[1]
                policy = (
                    line.split("(policy ")[1].split(")")[0]
                    if "(policy" in line
                    else None
                )
                if policy:
                    chain_policies[current_chain] = policy

                # Check default policies
        print("\nDefault Policy Check:")
        for chain in ["INPUT", "FORWARD", "OUTPUT"]:
            expected = getattr(default_policy, chain)
            actual = chain_policies.get(chain)
            if actual != expected:
                print(
                    f"  [NON-COMPLIANT] Chain {chain} policy is {actual}, should be {expected}"
                )
                current_score += get_score("critical")
                add_violation(
                    violation_log,
                    device["hostname"],
                    f"Default Policy {chain}",
                    "critical",
                    expected,
                    actual,
                    f"Please set {chain} policy to {expected}"
                )
            else:
                print(f"  [COMPLIANT] Chain {chain} policy is {expected}")

        stdin, stdout, _ = ssh_client.exec_command("sudo ufw status", get_pty=True)
        stdin.write(f"{password}\n")
        stdin.flush()
        ufw_status = stdout.read().decode()
        
        # Just IPv4 for now
       
        pattern = r'^(\d+)/(\w+)\s+(\w+)'
        # (port, protocol, action)
        all_ufw_lines = [m.groups() for line in ufw_status.splitlines() if (m := re.match(pattern, line.strip().lower()))]
        
        # Check firewall rules
        print("\nRule Check:")
        for rule in firewall_rules:
            rule_action_decoded = 'allow' if rule.action.lower() == 'accept' else 'block'
            actual = None
            for port, protocol, action in all_ufw_lines:
                if int(port) == rule.port and protocol.upper() == rule.protocol.upper():
                    actual = action
                    break
            
            if actual:
                if actual.lower() == rule_action_decoded:
                    print(
                        f"  [COMPLIANT] Port {rule.port}/{rule.protocol} correctly {actual}"
                    )
                else:
                    print(
                        f"  [NON-COMPLIANT] Port {rule.port}/{rule.protocol} is {actual}, should be {rule.action} (Severity: {rule.severity})"
                    )
                    current_score += get_score(rule.severity)
                    add_violation(
                        violation_log,
                        device["hostname"],
                        f"Port {rule.port}/{rule.protocol}",
                        rule.severity,
                        rule.action,
                        actual,
                        f"Please set port {rule.port}/{rule.protocol} to {rule.action}"
                    )
                continue
            
            if rule.type == "allowed" and chain_policies.get('INPUT') == 'DROP':
                print(
                    f"  [NON-COMPLIANT] Port {rule.port}/{rule.protocol} is not allowed but should be (Severity: {rule.severity})"
                )
                current_score += get_score(rule.severity)
                add_violation(
                    violation_log,
                    device["hostname"],
                    f"Port {rule.port}/{rule.protocol}",
                    rule.severity,
                    "Allowed",
                    "Not Allowed",
                    f"Please allow port {rule.port}/{rule.protocol}"
                )
                continue
            if rule.type == "blocked" and chain_policies.get('INPUT') == 'ACCEPT':
                print(
                    f"  [NON-COMPLIANT] Port {rule.port}/{rule.protocol} is not blocked but should be (Severity: {rule.severity})"
                )
                current_score += get_score(rule.severity)
                add_violation(
                    violation_log,
                    device["hostname"],
                    f"Port {rule.port}/{rule.protocol}",
                    rule.severity,
                    "Blocked",
                    "Not Blocked",
                    f"Please block port {rule.port}/{rule.protocol}"
                )
                continue
            print(f"  [COMPLIANT] Port {rule.port}/{rule.protocol} is correctly not present and covered by default policy")

    except Exception as e:
        print(f"  [ERROR] Failed to check firewall compliance: {str(e)}")
        print(traceback.format_exc())
    return current_score


def get_user_violations(user_rules, password_policy, ssh_client, violation_log, device):
    current_score = 0
    try:
        # Get list of users and their password aging info
        stdin, stdout, stderr = ssh_client.exec_command(
            'cat /etc/passwd; echo "---"; cat /etc/shadow'
        )
        output = stdout.read().decode()
        passwd_content, shadow_content = output.split("---")

        # Check required users
        for user_rule in user_rules:
            user_exists = any(
                line.startswith(f"{user_rule.username}:")
                for line in passwd_content.splitlines()
            )

            if user_rule.type == "required" and not user_exists:
                print(
                    f"  [NON-COMPLIANT] Required user '{user_rule.username}' not found (Severity: {user_rule.severity})"
                )
                current_score += get_score(user_rule.severity)
                add_violation(
                    violation_log,
                    device["hostname"],
                    f"User {user_rule.username}",
                    user_rule.severity,
                    "Exists",
                    "Not Found",
                    f"Please add user {user_rule.username}"
                )
            elif user_rule.type == "prohibited" and user_exists:
                print(
                    f"  [NON-COMPLIANT] Prohibited user '{user_rule.username}' exists (Severity: {user_rule.severity})"
                )
                current_score += get_score(user_rule.severity)
                add_violation(
                    violation_log,
                    device["hostname"],
                    f"User {user_rule.username}",
                    user_rule.severity,
                    "Not Exists",
                    "Exists",
                    f"Please remove user {user_rule.username}"
                )
            else:
                status = "exists" if user_rule.type == "required" else "does not exist"
                print(f"  [COMPLIANT] User '{user_rule.username}' {status}")

                # Check password policy
        print("\nPassword Policy Check:")
        stdin, stdout, stderr = ssh_client.exec_command("chage -l audituser")
        chage_output = stdout.read().decode()

        try:
            max_days = int(
                [line for line in chage_output.splitlines() if "Maximum" in line][
                    0
                ].split()[-1]
            )
            min_days = int(
                [line for line in chage_output.splitlines() if "Minimum" in line][
                    0
                ].split()[-1]
            )
            warn_days = int(
                [
                    line
                    for line in chage_output.splitlines()
                    if "warning" in line.lower()
                ][0].split()[-1]
            )

            if max_days > password_policy.max_days:
                print(
                    f"  [NON-COMPLIANT] Maximum password age ({max_days}) exceeds policy ({password_policy.max_days})"
                )
                current_score += get_score(user_rule.severity)
                add_violation(
                    violation_log,
                    device["hostname"],
                    "Password Policy",
                    user_rule.severity,
                    f"Max days <= {password_policy.max_days}",
                    f"{max_days}",
                    f"Please set to at most {password_policy.max_days}"
                )
            else:
                print("  [COMPLIANT] Maximum password age")

            if min_days < password_policy.min_days:
                print(
                    f"  [NON-COMPLIANT] Minimum password age ({min_days}) below policy ({password_policy.min_days})"
                )
                current_score += get_score(user_rule.severity)
                add_violation(
                    violation_log,
                    device["hostname"],
                    "Password Policy",
                    user_rule.severity,
                    f"Min days >= {password_policy.min_days}",
                    f"{min_days}",
                    f"Please set to at least {password_policy.min_days}"
                )
            else:
                print("  [COMPLIANT] Minimum password age")

            if warn_days < password_policy.warn_age:
                print(
                    f"  [NON-COMPLIANT] Password warning period ({warn_days}) below policy ({password_policy.warn_age})"
                )
                current_score += get_score(user_rule.severity)
                add_violation(
                    violation_log,
                    device["hostname"],
                    "Password Policy",
                    user_rule.severity,
                    f"Warn days >= {password_policy.warn_age}",
                    f"{warn_days}",
                    f"Please set to at least {password_policy.warn_age}"
                )
            else:
                print("  [COMPLIANT] Password warning period")

        except (IndexError, ValueError) as e:
            print(f"  [ERROR] Could not parse password aging information: {str(e)}")

    except Exception as e:
        print(f"  [ERROR] Failed to check user compliance: {str(e)}")
    return current_score


def get_ssh_violations(
    ssh_client, password, ssh_config_baseline, ssh_compliance_rules, violation_log, device
):
    current_score = 0
    # SSH config audit
    # Execute command to read sshd_config
    stdin, stdout, stderr = ssh_client.exec_command("sudo sshd -T", get_pty=True)
    stdin.write(f"{password}\n")
    stdin.flush()
    config_content = stdout.read().decode()

    ssh_config_baseline = {k.lower(): str(v).lower() for k, v in ssh_config_baseline.items()}
    # Parse the configuration content
    config = {}
    for line in config_content.splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#") or line.startswith("Include"):
            continue
        
        parts = line.split(None, 1)
        if len(parts) == 2:
            key, value = parts
            value = value.strip("\"'").lower()
            config[key] = value

    # SSH compliance check
    missing_keys = set(ssh_config_baseline.keys()) - set(config.keys())

    print("\nSSH Configuration Check:")
    if missing_keys:
        for key in missing_keys:
            print(f"  [MISSING] {key} - Expected '{ssh_config_baseline[key]}', found 'Not Set'")
            current_score += get_score("critical")
            add_violation(
                violation_log,
                device["hostname"],
                f"SSH Parameter {key}",
                "critical",
                ssh_config_baseline[key],
                "Not Set",
                f"Please set to {ssh_config_baseline[key]}"
            )


    for rule in ssh_compliance_rules:
        actual_value = config.get(rule.parameter.lower())
        if str(actual_value).lower() != rule.expected:
            print(
                f"  [NON-COMPLIANT] {rule.parameter} - Expected '{rule.expected}', found '{actual_value}' (Severity: {rule.severity})"
            )
            current_score += get_score(rule.severity)
            add_violation(
                violation_log,
                device["hostname"],
                f"SSH Parameter {rule.parameter}",
                rule.severity,
                rule.expected,
                actual_value if actual_value is not None else "Not Set",
                f"Please set to {rule.expected}"
            )
        else:
            print(f"  [COMPLIANT] {rule.parameter} is correctly set to '{rule.expected}'")

    return current_score


if __name__ == "__main__":
    violation_log = audit_all_devices()
    # Create reports directory if it doesn't exist
    os.makedirs("reports", exist_ok=True)

    # Generate filename with current timestamp
    filename = f"reports/audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    # Write violation log to JSON file
    with open(filename, "w") as f:
        json.dump(violation_log, f, indent=2)
    print(f"\nViolation log written to {filename}")
