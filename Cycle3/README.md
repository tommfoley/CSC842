# FTG Simulator

## Overview
FTG Simulator is a firewall configuration simulator designed to help teach/learn the fundamental concepts of creating firewall objects and policies. This tool has been purposely written to be CLI-based as opposed to GUI-based to help enforce the learners' confidence and familiarity with CLI-based environments, as they are still widely used. 

FTG Simulator gets its name from the underlying architecture of how students create objects, policies, and the formatting of the config file itself, which are all based on Fortinet FortiGate firewalls.The output of this tool is aligned closely enough with Fortigate configuration so that students can copy and paste their config files directly from this tool into a Fortigate, allowing for consistency in learning across more advanced and robust lab environments.

This tool was written in Python 3.10.12 and has been tested on Linux.

## Dependencies
* Python 3

## To Execute
Simply run the python file. 

```bash
python3 FTG_Simulator.py
```
The user is presented with the following menu:

```bash
   _______________  _____            __     __          
  / __/_  __/ ___/ / __(_)_ _  __ __/ /__ _/ /____  ____
 / _/  / / / (_ / _\ \/ /  ' \/ // / / _ `/ __/ _ \/ __/
/_/   /_/  \___/ /___/_/_/_/_/\_,_/_/\_,_/\__/\___/_/                                                        
              
1. Check/Create Config File
2. Create new object
3. Create new policy
0. Exit
```
Generally, the program modules should be run in order as displayed. It is recommended to have the Check/Create Config File module create new config files rather than starting from a blank file that was manually created.  

## Future Work
* Split the program into multiple modules
* Print colored text
* Create package(s) for easier distribution to students
* **FTG Grader**: A tool to help instructors automatically grade student's config files. 
