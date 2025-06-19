################
### Includes ###
################

import csv
import os
import argparse

#######################
### Global Variable ###
#######################

answer_path = "answer.conf"
student_dir = "student_configs"
output_dir = "reports"
total_points = 100

#################
### Functions ###
#################

#
# Parses config files.
#
def parse_fortigate_config(path):
    with open(path, 'r') as f:
        lines = [line.strip() for line in f if line.strip()]

    config = {}
    stack = []
    current = config
    current_key = None

    for line in lines:

        #If line starts with config keyword, this is a new section of the config file
        if line.startswith("config "):
            section = line.split(" ", 1)[1]
            new_section = {}
            current[section] = new_section
            stack.append((current, section))
            current = new_section

        # If line starts with edit keyword, this is a new object within a section
        elif line.startswith("edit "):
            name = line.split(" ", 1)[1].strip('"')
            if "edit_blocks" not in current:
                current["edit_blocks"] = {}
            current["edit_blocks"][name] = {}
            stack.append((current, name))
            current = current["edit_blocks"][name]

        # Ignore uuids as these are always different
        elif line.startswith("set uuid "):
            pass

        # If line starts with set keyword, this is something that we should extract for grading
        elif line.startswith("set "):
            parts = line.split(" ", 2)
            key = parts[1]
            value = parts[2] if len(parts) > 2 else ""
            current[key] = value

        # If we reached the end of a section or the file, remove from the stack to start parsing new section
        elif line == "next" or line == "end":
            current, current_key = stack.pop()

    return config

#
# Compares dictionaries created by parse function.
#
def compare_dictionaries(student, answer, path=""):
    differences = []

    # Compare answer key against student file
    for key in answer:

        # String comparisons
        if isinstance(answer[key], str) and isinstance(student[key], str):
            # If the answers are identical, nothing to do
            if answer[key].lower() == student[key].lower():
                pass
            # If answer is in student, possible a partial
            elif answer[key].lower() in student[key].lower():
                differences.append((path + "/" + key, "Partial", answer[key], student[key]))
            # Same as above, but strip quotes to compare inner strings
            elif answer[key].lower().strip('"') in student[key].lower().strip('"'):
                differences.append((path + "/" + key, "Partial", answer[key], student[key]))
            # At this point the answers don't match
            elif student[key] != answer[key]:
                differences.append((path + "/" + key, "Mismatch", answer[key], student[key]))

        # The correct answer is not in the student file
        elif key not in student:
            differences.append((path + "/" + key, "Missing", answer[key], ""))

        # If the answer is nested (dict within a dict), call the function again
        elif isinstance(answer[key], dict):
            differences.extend(compare_dictionaries(student[key], answer[key], path + "/" + key))

    # Compare student to answer key to find anything extra they put in their config file
    for key in student:
        if key not in answer:
            differences.append((path + "/" + key, "Extra", "", student[key]))

    return differences

#
# Generates CSV report for each student from the differences list generatd by the compare function.
#

def generate_report(student_file, differences, output_dir):
    student_name = os.path.splitext(os.path.basename(student_file))[0]
    report_path = os.path.join(output_dir, f"{student_name}_report.csv")

    with open(report_path, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Path", "Type", "Expected", "Found"])
        writer.writerows(differences)

    return report_path

#
# Grades student config, prints out info to the user, then generates a CSV report.
#
def grade_student_configs(answer_path, student_dir, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    answer_config = parse_fortigate_config(answer_path)

    summary = []

    for filename in os.listdir(student_dir):
        if filename.endswith(".conf"):
            student_path = os.path.join(student_dir, filename)
            student_name = os.path.splitext(filename)[0]
            print(f"🔍 Grading {student_name}...")

            student_config = parse_fortigate_config(student_path)
            differences = compare_dictionaries(student_config, answer_config)
            report_path = generate_report(student_path, differences, output_dir)
            score = max(0, total_points - len(differences))

            summary.append((student_name, len(differences), score, report_path))

    return summary

def main(interactive=False):
    global answer_path, student_dir, output_dir, total_points

    if interactive:
        # Ask user for answer key
        answer_path = input("Enter location of the answer key (default: answer.conf): ").strip() or "answer.conf"

        # Ask user for student file directory
        student_dir = input("Enter folder where student files are located (default: student_configs): ").strip() or "student_configs"

        # Ask user for report output folder
        output_dir = input("Enter folder where student reports should be created (default: reports): ").strip() or "reports"

        # Ask user for points possible
        total_points = int(input("Enter total points possible for the assignment (default: 100): ").strip()) or 100
    else:
        pass

    print("📘 Loading answer key...")
    summary = grade_student_configs(answer_path, student_dir, output_dir)

    print("\n📊 Summary Report:")
    print(f"{'Student':<25} {'Differences':<12} {'Score':<6} {'Report File'}")
    print("-" * 70)
    for name, diff_count, score, report in summary:
        print(f"{name:<25} {diff_count:<12} {score:<6} {report}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run in interactive or silent mode.")
    parser.add_argument("-i","--interactive", action="store_true", help="Run in interactive mode")
    args = parser.parse_args()

    main(interactive=args.interactive)
