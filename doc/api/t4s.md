# T4S Claims / Scopes


## Define scopes

tenant-config.yml


```
scopes:
    "profile":
        - "name"
        - "email"
        
    "user:read":
        - "name"
        - "email"
        
    "storage:reports:byuser":
        - "storage:mongo:reports:%u:+rw"

```


## Define allowed scopes 

<clientId>.yml

frontend-client.yml:

```yaml
allowed_scopes:
    - "storage:reports:byuser"
   
```


reports-client.yml:

```yaml
allowed_scopes:
    - "storage:mongo:reports:list"

```



