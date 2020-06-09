# t4s storage api


## T4s config


default-org.yml

```
claims:
    - "datastore:mongo:reports:data:%u:+rw"
    - "datastore:mongo:reports:data:%o:+rw"

```

scope.yml

```
profile:
    - ""
    
```


## Store Data

Required Claims: `datastore:mongo:reports:data:%u:+rw`

Required Claims: `datastore:mongo:groupsettings:%o:+rw`




POST

```
https://storagehost.de/v1/mongo/reports/data/<uuid>
https://storagehost.de/v1/mongo/reports/list

https://storagehost.de/v1/mongo/groupsettings/orgid234
```


## Store data for a organization





## List data

Required Claims: `datastore:mongo:reports:list`


Required Claims: `datastore:mongo:reports:*:+r`



