# Fortigate Firewall Rule Analyzer / Parser

## About
- This application was created for myslef for security review of fortifate firewall rules.
- The information about the groups listed in the source, destination, and services columns is not included in the conventional firewall rule export. 
- To free up time for the real evaluation, we have attempted to automate repetitive and tedious tasks.
- The report will be a Microsoft Excel file in the.xlsx format with some basic formatting. Feel free to remove unnecessory columns and format as per your requirements.

## Features
- Provides enriched details about the items which are part of groups configured in source, destination and services columns.
- Detects duplicate rules by comparing source, destination, ports and interfaces.
- Detects any-any configurations in source, destination and services section.
- Detects if no security profiles are configured for the rule.
- Detects if no logging is enabled for the rule.
- Detects if no traffic is going through the rule (You need to rename traditional fortigate csv export and upload it in the tool)
- Can enrich the "Previous Client Remarks" from the old report (.xlsx format and report should comtains policy ID and client remarks in same row)

Limitations:
- Does not supports overlapping rule detections (Please review this manually).
- Need manual review The observations and recommendations given by the tool if there are any exceptions.
