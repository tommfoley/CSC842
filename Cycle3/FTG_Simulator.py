################
### Includes ###
################

import os
import uuid
import getpass

#######################
### Global Variable ###
#######################
config_file = ""


#################
### Functions ###
#################

#
# Creates and adds firwall address objects to the config file.
#
def append_firewall_address_items(filename):
    global config_file
    if config_file == "":
    	print("Oops, config file was not defined.")
    	ensure_config_file_exists()
    else:
        new_entries = []

        while True:
            name = input("Enter address object name (or press Enter to finish): ").strip()
            if not name:
                break

            addr_uuid = str(uuid.uuid4())
            entry_type = input("Enter type (ip or fqdn): ").strip().lower()

            entry_lines = [f'    edit "{name}"', f'        set uuid {addr_uuid}']

            if entry_type == "fqdn":
                fqdn_value = input("Enter FQDN: ").strip()
                entry_lines.append('        set type fqdn')
                entry_lines.append(f'        set fqdn "{fqdn_value}"')
            else:
                subnet_ip = input("Enter subnet IP: ").strip()
                subnet_mask = input("Enter subnet mask: ").strip()
                entry_lines.append(f'        set subnet {subnet_ip} {subnet_mask}')

            entry_lines.append('    next')
            new_entries.append('\n'.join(entry_lines))

        if not new_entries:
            print("No new address objects to add.\
                    \n----------------------------------------------")
            return

        with open(filename, 'r') as file:
            lines = file.readlines()

        # Find where to insert inside "config firewall address" :: AI Assisted method
        output = []
        in_section = False
        for i, line in enumerate(lines):
            output.append(line)
            if line.strip() == "config firewall address":
                in_section = True
            elif in_section and line.strip() == "end":
                # Insert before this 'end'
                output = output[:-1] + ['\n'.join(new_entries) + '\n'] + [line] + lines[i+1:]
                break

        with open(filename, 'w') as file:
            file.writelines(output)

        print("Address objects added successfully.")

#
# Creates and adds firwall policy objects to the config file.
#

def append_firewall_policy_items(filename):
    global config_file
    if config_file == "":
    	print("Oops, config file was not defined.")
    	ensure_config_file_exists()
    else:
        new_entries = []
        next_edit_number = 1000

        while True:
            name = input("Enter policy name (or press Enter to finish): ").strip()
            if not name:
                break

            policy_uuid = str(uuid.uuid4())
            srcintf = input("Enter source interface: ").strip()
            dstintf = input("Enter destination interface: ").strip()
            srcaddr = input("Enter source address: ").strip()
            dstaddr = input("Enter destination address: ").strip()
            action = input("Enter action (accept/deny): ").strip().lower()
            schedule = input("Enter schedule (default: always): ").strip() or "always"
            service = input("Enter service: ").strip()
            nat = input("Enable NAT? (yes/no): ").strip().lower()

            entry_lines = [
                f'    edit {next_edit_number}',
                f'        set name "{name}"',
                f'        set uuid {policy_uuid}',
                f'        set srcintf "{srcintf}"',
                f'        set dstintf "{dstintf}"',
                f'        set srcaddr "{srcaddr}"',
                f'        set dstaddr "{dstaddr}"',
                f'        set action {action}',
                f'        set schedule "{schedule}"',
                f'        set service "{service}"'
            ]

            if nat == "yes":
                entry_lines.append('        set nat enable')

            entry_lines.append('    next')
            new_entries.append('\n'.join(entry_lines))
            next_edit_number += 1

        if not new_entries:
            print("No new policies to add.")
            return

        with open(filename, 'r') as file:
            lines = file.readlines()

        # Find where to insert inside "config firewall policy" :: AI Assisted method
        output = []
        in_section = False
        for i, line in enumerate(lines):
            output.append(line)
            if line.strip() == "config firewall policy":
                in_section = True
            elif in_section and line.strip() == "end":
                output = output[:-1] + ['\n'.join(new_entries) + '\n'] + [line] + lines[i+1:]
                break

        with open(filename, 'w') as file:
            file.writelines(output)

        print("Firewall policies added successfully.")

#
# Ensures the config file exists or creates one if none exist. Default value is set to current OS user # + _config.conf
#

def ensure_config_file_exists():
    global config_file
    filename = input("Enter the full name of the config file (including .conf extension): ") or getpass.getuser()+"_config.conf"
    if not os.path.exists(filename):
        with open(filename, 'w') as file:
            file.write("config firewall address\nend\n\nconfig firewall policy\nend")
        config_file = filename
        print(f"{filename} did not exist and has been created with default structure.")
    else:
        print(f"{filename} already exists. Continued use of the program will alter data in the file.")

#
# Displays user friendly menu. ASCII art generated by: https://patorjk.com/software/taag/
#

def display_menu(options):
    print("""
   _______________  _____            __     __
  / __/_  __/ ___/ / __(_)_ _  __ __/ /__ _/ /____  ____
 / _/  / / / (_ / _\ \/ /  ' \/ // / / _ `/ __/ _ \/ __/
/_/   /_/  \___/ /___/_/_/_/_/\_,_/_/\_,_/\__/\___/_/
              """)
    for i, option in enumerate(options):
        print(f"{i + 1}. {option}")
    print("0. Exit\n")
    print("----------------------------------------------")

#
# Get user menu choice
#

def get_choice(options):
    while True:
        try:
            choice = int(input("Enter your choice: "))
            if 0 <= choice <= len(options):
                return choice
            else:
                print("Invalid choice. Please try again.")
        except ValueError:
            print("Invalid input. Please enter a number.")


####################
### Main Program ###
####################

def main():
    options = ["Check/Create Config File", "Create new object", "Create new policy"]
    while True:
        display_menu(options)
        choice = get_choice(options)

        if choice == 0:
            print("Exiting...")
            break
        #
        # If user chooses to define or create config file
        #
        elif choice == 1:
            print("Checking/Creating config file...")
            try:
                ensure_config_file_exists()
            except PermissionError:
                print("There was a permission issue accessing the config file.\
                \n----------------------------------------------")
                sys.exit(1)
            except KeyboardInterrupt:
                print("\nKeyboard Interrupt: User exited config file checker.\
                \n----------------------------------------------")
            except Exception as e:
                print(f"An error occurred: {e}\
                \n----------------------------------------------")
                sys.exit(1)
        #
        # If user chooses to create address object
        #
        elif choice == 2:
            print("Entering Object Creator Tool...")
            try:
                append_firewall_address_items(config_file)
            except PermissionError:
                print("There was a permission issue accessing the config file.\
                \n----------------------------------------------")
                sys.exit(1)
            except KeyboardInterrupt:
                print("\nKeyboard Interrupt: User exited object creator.\
                \n----------------------------------------------")
            except Exception as e:
                print(f"An error occurred: {e}\
                \n----------------------------------------------")
                sys.exit(1)
        #
        # If user chooses to create policy object
        #

        elif choice == 3:
            print("Entering Policy Creator Tool...")
            try:
                append_firewall_policy_items(config_file)
            except PermissionError:
                print("There was a permission issue accessing the config file.\
                \n----------------------------------------------")
                sys.exit(1)
            except KeyboardInterrupt:
                print("\nKeyboard Interrupt: User exited policy creator.\
                \n----------------------------------------------")
            except Exception as e:
                print(f"An error occurred: {e}\
                \n----------------------------------------------")
                sys.exit(1)


if __name__ == "__main__":
    main()
