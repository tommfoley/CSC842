# FTG Grader

## Overview

FTG Grader is a tool that is designed to be used in conjunction with the firewall configuration simulator (FTG Simulator). This tool will take student config files and an answer key and grade them for the instructor. 

This tool will run in silent mode by default to speed up the grading process or in an interactive mode if the default arguments need to be changed.

This tool was written in Python 3.10.12 and has been tested on Linux.

## Dependencies
* Python 3

## Folder Structure

```
project_root/
├── FTG_Grader.py
├── answer.conf
├── student_configs/
└── reports/

```

## To Execute (Non-Interactive)

Simply run the Python file. 

```bash 
python3 FTG_Grader.py
```

## To Execute (Interactive)

Simply run the Python file. 

```bash

python3 FTG_Grader.py -i

```

## Future Work
* Create a GUI or web interface.
* If an 'edit' block is misspelled, the program reports it as missing rather than a mismatch.
* Address object's subnet that are a partial match are reported as a mismatch. 
* Grade values are not written to the student report files. (Possible FERPA Issue)
