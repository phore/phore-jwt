# Szenarios for using Storage API


| Component | Descritpion |
|-----------|-------------|
| `:topic`  | Define name of the storage entity (freely defined) |



## Resource Owner (User) individual

Szenario: The FE wants to store/load user defined settings regarding to
the layout / theme etc. This information should be only present to the
FE client.

### Read write

Read Requires: user.storage || user.storage.read || user.storage.:topic || user.storage.:topic.read

Write Requires: user.storage || user.storage.:topic

```
https://storageapi/v1/doc/user/:topic
```

### List
Szenario: FE offers a form to display and adjust settings for a Reporting
Service. The Reporting services needs a list of all users with this topic
assigned and the settings there.

Requires: users.list & users.topic.:topic.read

***Request:***
```
https://storageapi/v1/doc/user/:topic/list?scope=email
```

***Response:***
```json
{
  "results_total": 512,
  "limit": 2000,
  "page": 1,
  "result": [
    {
      "user_id": "4j02kjal9i4h4",
      "email": "some@email.com",
      "data": {"document": "data"}
    }
  ] 
}
```


## Organisation individual

Problem: It is not yet clear if a user can switch between organizations
or if data from all organizations is is unified. In the last case we have
to specify the actual organizsation we want to store data for

***To be refined***

```
https://storageapi/v1/doc/org/:topic?orgid=xxx
```
### List route

```
https://storageapi/v1/doc/org/
```

## Client individual

Szenario: A dedicated service wants to store some metadata about
it's internal state and make it accessible to all other instances
with the same clientId

(Requires Client Authentication)

```
https://storageapi/v1/doc/client/:topic
```
