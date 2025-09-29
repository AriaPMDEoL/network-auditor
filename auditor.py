import yaml
import paramiko
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple, Literal

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
        with open(filepath, 'r') as file: # open the file safely, and return the devices
            inventory = yaml.safe_load(file)
            return inventory.get('devices', [])
    except FileNotFoundError:
        print(f"Error: Could not find {filepath}")
        return []
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file: {e}")
        return []

def get_remote_sshd_config(hostname: str, ip: str, username: str, password: str) -> Tuple[Dict[str, str], Optional[str]]:
    """
    Connect to a remote host and retrieve its sshd_config file contents.
    
    Args:
        hostname (str): Device hostname
        ip (str): Device IP address
        username (str): SSH username
        password (str): SSH password
        
    Returns:
        Tuple[Dict[str, str], Optional[str]]: Tuple containing:
            - Dictionary of SSH configuration parameters and their values
            - Error message if something went wrong, None otherwise
    """
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        ssh_client.connect(
            ip,
            username=username,
            password=password,
            timeout=10
        )
        
        # Execute command to read sshd_config
        stdin, stdout, stderr = ssh_client.exec_command('cat /etc/ssh/sshd_config')
        config_content = stdout.read().decode()
        
        # Parse the configuration content
        config = {}
        for line in config_content.splitlines():
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('Include'):
                continue
            
            parts = line.split(None, 1)
            if len(parts) == 2:
                key, value = parts
                value = value.strip('"\'')
                config[key] = value
                
        return config, None
        
    except Exception as e:
        return {}, f"Error connecting to {hostname} ({ip}): {str(e)}"
        
    finally:
        ssh_client.close()

@dataclass
class ComplianceRule:
    """Data class representing an SSH compliance rule"""
    rule: str
    parameter: str
    expected: str
    severity: str

def parse_ssh_baseline(filepath: str = "baselines/ssh_baseline.yaml") -> Tuple[Dict[str, str], List[ComplianceRule]]:
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
        with open(filepath, 'r') as file:
            baseline = yaml.safe_load(file)
            
            # Parse SSH config dictionary
            ssh_config = baseline.get('ssh_config', {})
            
            # Parse compliance rules into dataclass objects
            compliance_rules = [
                ComplianceRule(
                    rule=rule['rule'],
                    parameter=rule['parameter'],
                    expected=rule['expected'],
                    severity=rule['severity']
                )
                for rule in baseline.get('compliance_rules', [])
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

def parse_users_baseline(filepath: str = "baselines/users_baseline.yaml") -> Tuple[List[UserRule], PasswordPolicy]:
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
        with open(filepath, 'r') as file:
            baseline = yaml.safe_load(file)
            
            # Parse required users
            required_users = [
                UserRule(
                    username=user['username'],
                    description=user['description'],
                    severity=user['severity'],
                    type="required"
                )
                for user in baseline.get('required_users', [])
            ]
            
            # Parse prohibited users
            prohibited_users = [
                UserRule(
                    username=user['username'],
                    description=user['description'],
                    severity=user['severity'],
                    type="prohibited"
                )
                for user in baseline.get('prohibited_users', [])
            ]
            
            # Parse password policy
            policy_data = baseline.get('password_policy', {})
            password_policy = PasswordPolicy(
                max_days=policy_data.get('max_days', 99999),
                min_days=policy_data.get('min_days', 0),
                warn_age=policy_data.get('warn_age', 7)
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

def parse_firewall_baseline(filepath: str = "baselines/firewall_baseline.yaml") -> Tuple[List[FirewallRule], DefaultPolicy]:
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
        with open(filepath, 'r') as file:
            baseline = yaml.safe_load(file)
            
            # Parse required (allowed) rules
            allowed_rules = [
                FirewallRule(
                    port=rule['port'],
                    protocol=rule['protocol'],
                    action=rule['action'],
                    description=rule['description'],
                    severity=rule['severity'],
                    type="allowed"
                )
                for rule in baseline.get('required_rules', [])
            ]
            
            # Parse blocked rules
            blocked_rules = [
                FirewallRule(
                    port=rule['port'],
                    protocol=rule['protocol'],
                    action=rule['action'],
                    description=rule['description'],
                    severity=rule['severity'],
                    type="blocked"
                )
                for rule in baseline.get('blocked_rules', [])
            ]
            
            # Parse default policy
            policy_data = baseline.get('default_policy', {})
            default_policy = DefaultPolicy(
                INPUT=policy_data.get('INPUT', 'DROP'),
                FORWARD=policy_data.get('FORWARD', 'DROP'),
                OUTPUT=policy_data.get('OUTPUT', 'ACCEPT')
            )
            
            return allowed_rules + blocked_rules, default_policy
            
    except FileNotFoundError:
        print(f"Error: Could not find {filepath}")
        return [], DefaultPolicy('DROP', 'DROP', 'ACCEPT')
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file: {e}")
        return [], DefaultPolicy('DROP', 'DROP', 'ACCEPT')

def audit_all_devices():
    """
    Connect to all devices in inventory and retrieve their configurations.
    """
    # Read all baseline configurations
    ssh_config_baseline, ssh_compliance_rules = parse_ssh_baseline()
    user_rules, password_policy = parse_users_baseline()
    firewall_rules, default_policy = parse_firewall_baseline()
    devices = parse_device_inventory()

    for device in devices:
        print(f"\nAuditing {device['hostname']} ({device['ip']})...")
        
        # SSH config audit
        config, error = get_remote_sshd_config(
            device['hostname'],
            device['ip'],
            device['username'],
            device['password']
        )
        
        if error:
            print(error)
            continue

        print(f"Successfully retrieved SSH config from {device['hostname']}")
        
        # SSH compliance check
        config_normalized = {k.lower(): v for k, v in ssh_config_baseline.items()}
        config_normalized.update({k.lower(): v for k, v in config.items()})
        
        print("\nSSH Compliance Check:")
        for rule in ssh_compliance_rules:
            actual_value = config_normalized.get(rule.parameter.lower())
            if actual_value is None:
                print(f"  [MISSING] {rule.rule} - Parameter '{rule.parameter}' not found (Severity: {rule.severity})")
            elif rule.expected.isdigit() and str(actual_value).isdigit():
                if int(actual_value) > int(rule.expected):
                    print(f"  [NON-COMPLIANT] {rule.rule} - Expected at most '{rule.expected}', found '{actual_value}' (Severity: {rule.severity})")
                else:
                    print(f"  [COMPLIANT] {rule.rule}")
            elif actual_value != rule.expected:
                print(f"  [NON-COMPLIANT] {rule.rule} - Expected '{rule.expected}', found '{actual_value}' (Severity: {rule.severity})")
            else:
                print(f"  [COMPLIANT] {rule.rule}")

        # User compliance check
        print("\nUser Account Check:")
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh_client.connect(
                device['ip'],
                username=device['username'],
                password=device['password'],
                timeout=10
            )
            try:
                
                
                # Get list of users and their password aging info
                stdin, stdout, stderr = ssh_client.exec_command('cat /etc/passwd; echo "---"; cat /etc/shadow')
                output = stdout.read().decode()
                passwd_content, shadow_content = output.split('---')
                
                # Check required users
                for user_rule in user_rules:
                    user_exists = any(line.startswith(f"{user_rule.username}:") 
                                    for line in passwd_content.splitlines())
                    
                    if user_rule.type == "required" and not user_exists:
                        print(f"  [NON-COMPLIANT] Required user '{user_rule.username}' not found (Severity: {user_rule.severity})")
                    elif user_rule.type == "prohibited" and user_exists:
                        print(f"  [NON-COMPLIANT] Prohibited user '{user_rule.username}' exists (Severity: {user_rule.severity})")
                    else:
                        status = "exists" if user_rule.type == "required" else "does not exist"
                        print(f"  [COMPLIANT] User '{user_rule.username}' {status}")
                
                # Check password policy
                print("\nPassword Policy Check:")
                stdin, stdout, stderr = ssh_client.exec_command('chage -l audituser')
                chage_output = stdout.read().decode()
                
                try:
                    max_days = int([line for line in chage_output.splitlines() 
                                if "Maximum" in line][0].split()[-1])
                    min_days = int([line for line in chage_output.splitlines() 
                                if "Minimum" in line][0].split()[-1])
                    warn_days = int([line for line in chage_output.splitlines() 
                                if "warning" in line.lower()][0].split()[-1])
                    
                    if max_days > password_policy.max_days:
                        print(f"  [NON-COMPLIANT] Maximum password age ({max_days}) exceeds policy ({password_policy.max_days})")
                    else:
                        print(f"  [COMPLIANT] Maximum password age")
                        
                    if min_days < password_policy.min_days:
                        print(f"  [NON-COMPLIANT] Minimum password age ({min_days}) below policy ({password_policy.min_days})")
                    else:
                        print(f"  [COMPLIANT] Minimum password age")
                        
                    if warn_days < password_policy.warn_age:
                        print(f"  [NON-COMPLIANT] Password warning period ({warn_days}) below policy ({password_policy.warn_age})")
                    else:
                        print(f"  [COMPLIANT] Password warning period")
                        
                except (IndexError, ValueError) as e:
                    print(f"  [ERROR] Could not parse password aging information: {str(e)}")
                    
            except Exception as e:
                print(f"  [ERROR] Failed to check user compliance: {str(e)}")
            

            # Add firewall compliance check
            print("\nFirewall Rules Check:")
            try:
                # Get iptables rules
                _, stdout, _ = ssh_client.exec_command('sudo iptables -L -n')
                iptables_output = stdout.read().decode()
                
                # Get default policies
                # i dont think i understand the zero packets, zero bytes. are we not pulling out the right information?
                # if accepting nothing is the same as dropping it, then why is our output policy not anything either?
                chain_policies = {}
                current_chain = None
                for line in iptables_output.splitlines():
                    if line.startswith('Chain'):
                        current_chain = line.split()[1]
                        policy = line.split('(policy ')[1].split(')')[0] if '(policy' in line else None
                        if policy:
                            chain_policies[current_chain] = policy

                # Check default policies
                print("\nDefault Policy Check:")
                for chain in ['INPUT', 'FORWARD', 'OUTPUT']:
                    expected = getattr(default_policy, chain)
                    actual = chain_policies.get(chain)
                    if actual != expected:
                        print(f"  [NON-COMPLIANT] Chain {chain} policy is {actual}, should be {expected}")
                    else:
                        print(f"  [COMPLIANT] Chain {chain} policy is {expected}")

                # Check firewall rules
                print("\nRule Check:")
                for rule in firewall_rules:
                    rule_pattern = f"{rule.protocol.upper()}.*dpt:{rule.port}"
                    rule_exists = any(rule_pattern in line for line in iptables_output.splitlines())
                    
                    # why is it always saying that the ports are blocked/dropped/not allowed when they are?
                    # i think the input/forward/output policy is an issue too
                    # because theyre NOT correctly DROP. they should be ACCEPT.
                    if rule.type == "allowed" and not rule_exists:
                        print(f"  [NON-COMPLIANT] Required port {rule.port}/{rule.protocol} not allowed "
                            f"(Severity: {rule.severity})")
                    elif rule.type == "blocked" and rule_exists:
                        print(f"  [NON-COMPLIANT] Port {rule.port}/{rule.protocol} should be blocked "
                            f"(Severity: {rule.severity})")
                    else:
                        status = "allowed" if rule.type == "allowed" else "blocked"
                        print(f"  [COMPLIANT] Port {rule.port}/{rule.protocol} correctly {status}")

            except Exception as e:
                print(f"  [ERROR] Failed to check firewall compliance: {str(e)}")
        except Exception as e:
            print(f"  [ERROR] Could not connect to device {device['ip']}: {str(e)}")
        finally:
            ssh_client.close()
if __name__ == "__main__":
    audit_all_devices()
