# Szenarios for using Storage API


## Resource Owner (User) individual

Szenario: The FE wants to store/load user defined settings regarding to
the layout / theme etc. This information should be only present to the
FE client.

### FE read / write settings

- Claim included: `user.storage` & `uid`


1) User visits settings page
    -> GET: `https://storageapi/v1/doc/user/reports-settings`

2) User changes settings
    -> POST: `https://storageapi/v1/doc/user/reports-settings`
    Body: `{active: true, interval: 24}`



### Generate Reports

1) Report service is triggered (cron) and retrieves list
    -> GET `https://storageapi/v1/doc/user/reports-settings/list?scope=email`
    RESPONSE
    ```json
    {
      "results_total": 2,
      "limit": 2000,
      "page": 1,
      "result": [
        {
          "user_id": "4j02kjal9i4h4",
          "email": "some@email.com",
          "data": {"active": true, "interval":  24}
        },
        {
          "user_id": "nextUser",
          "email": "some@email2.com",
          "data": {"active": true, "interval":  24}
        }
      ] 
    }
    ```
**Background**
- get list of all active users from t4s
- query api for data section?

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
