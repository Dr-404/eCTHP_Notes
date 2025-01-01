# Using regex in splunk

## Extract email from query 

```bash
amber
| rex field=_raw "(?i)\b(?<extracted_email>[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"
| eval email=extracted_email
| dedup email
| table email
```

## Hunt password bruteforce attack and identified password list and password length

```bash
index="botsv1" sourcetype="stream:http" dest_ip=192.168.250.70 http_method=POST form_data=*user*pass* 
| rex field=form_data "passwd=(?<password>\w+)" 
| eval passlen=len(password) 
| table _time form_data password passlen
```
- `rex`     : Regular expression
- `field=form_data` : Specifies that the extraction will be performed on the `form_data` field.
- `passwd=(?<password>\w+)` : 
    - Looks for the word passwd= in the form data
    - Captures the text immediately after passwd= that matches the regex \w+ (alphanumeric characters).
    - Stores this captured text in a new field called userpassword.
- `table` : Create Table view using specific data field
