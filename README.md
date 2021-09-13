HackerOne integration allows users to fetch reports by using the fetch incidents capability. It also provides commands to retrieve all the reports and programs.
This integration was integrated and tested with API version v1 of HackerOne.

## Filtering
For the command hackone-report-list as well as for the configuration parameter advanced_filter is provided to filter the response by attribute values.
The general filtering syntax is as follows:

```{\"attribute\": \"value1, value2\"}```
- `attribute` is the name of the attribute that the filter will be applied against.
- `value` is the value being checked for. You can specify multiple values as a comma-separated list for the attributes that are accepting the multiple values according to the API document.
- To specify multiple filters, use the comma ( , ) to separate them 
  (for example, `{\"attribute1 \": \"value1, value2\", \"attribute2\" : \"value3, value4\"}`).

To get the detailed information regarding the valid attributes for filtering user can refer to the [HackerOne API documentation](https://api.hackerone.com/customer-resources/#reports-get-all-reports).

## Configure HackerOne on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for HackerOne.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL | Server URL to connect to HackerOne. | True |
    | Username | The username of the user. | True |
    | Maximum number of incidents per fetch | The maximum limit is 100. | True |
    | First fetch time interval | Date or relative timestamp to start fetching incidents from. \(Formats accepted: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ, etc\) | False |
    | Program Handle | Fetches reports based on the specified program handle.<br/>Note: Supports comma separated values. | True |
    | Advanced Filters | Fetches incidents based on the advanced filters.<br/>Note: Enter values in key-value JSON format. To separate multiple values of a single attribute, use commas.<br/>Format accepted: \{"attribute1": "value1, value2", "attribute2" : "value3, value4"\}<br/>For example: \{"closed_at__gt":"2020-10-26T10:48:16.834Z","reporter_agreed_on_going_public":"false"\} | False |
    | Use system proxy settings |  | False |
    | Trust any certificate (not secure) |  | False |
    | Incident type |  | False |
    | Fetch incidents |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### hackerone-report-list
***
Retrieves all the reports based on program handle and provided arguments.


#### Base Command

`hackerone-report-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| program_handle | The program handle to fetch the reports based on the specified handle.<br/>Note: Supports comma separated values. | Required | 
| sort_by | Sort the reports based on the attributes provided. Valid attributes are: swag_awarded_at, bounty_awarded_at, last_reporter_activity_at, first_program_activity_at, last_program_activity_at, triaged_at, created_at, closed_at, last_public_activity_at, last_activity_at, disclosed_at.<br/>Note: The default sort order for an attribute is ascending. Prefix the attributes with a hyphen to sort in descending order. Supports comma separated values.<br/>Example: -last_reporter_activity_at, created_at. | Optional | 
| page_size | The number of reports to retrieve per page. <br/>Note: Possible values are between 1 and 100. Default is 50. | Optional | 
| page_number | Page number to retrieve the reports from the specified page. | Optional | 
| advanced_filter | Filter the list of reports by attribute values.<br/>Note: Enter values in key-value JSON format. To separate multiple values of a single attribute, use commas. Add backslash(\) before quotes.<br/>Format accepted: {\"attribute1 \": \"value1, value2\", \"attribute2\" : \"value3, value4\"}<br/>For example: {\"created_at__gt\":\"2020-10-26T10:48:16.834Z\",\"severity\":\"low\"}. | Optional | 
| filter_by_keyword | The keyword filter to retrieve the reports by title and keywords. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HackerOne.Report.id | String | The unique ID of the report. | 
| HackerOne.Report.type | String | The type of the object of HackerOne. | 
| HackerOne.Report.attributes.title | String | The title of the report. | 
| HackerOne.Report.attributes.state | String | The state of the Report. It can be new, pending-program-review, triaged, needs-more-info, resolved, not-applicable, informative, duplicate, spam or retesting. | 
| HackerOne.Report.attributes.created_at | Date | The date and time the object was created. Formatted accordingto ISO 8601. | 
| HackerOne.Report.attributes.vulnerability_information | String | Detailed information about the vulnerability including the steps to reproduce as well as supporting material and references. | 
| HackerOne.Report.attributes.triaged_at | Date | The date and time the object was triaged. Formatted according to ISO 8601. | 
| HackerOne.Report.attributes.closed_at | Date | The date and time the object was closed. Formatted according to ISO 8601. | 
| HackerOne.Report.attributes.last_reporter_activity_at | String | The date and time that the most recent reporter activity was posted on the report.Formatted according to ISO 8601. | 
| HackerOne.Report.attributes.first_program_activity_at | String | The date and time that the first program activity was posted on the report.Formatted according to ISO 8601. | 
| HackerOne.Report.attributes.last_program_activity_at | String | The date and time that the most recent program activity was posted on the report.Formatted according to ISO 8601. | 
| HackerOne.Report.attributes.bounty_awarded_at | String | The date and time that the most recent bounty was awarded on the report.Formatted according to ISO 8601. | 
| HackerOne.Report.attributes.swag_awarded_at | String | The date and time that the most recent swag was awarded on the report.Formatted according to ISO 8601. | 
| HackerOne.Report.attributes.disclosed_at | String | The date and time the report was disclosed. Formatted according to ISO 8601. | 
| HackerOne.Report.attributes.reporter_agreed_on_going_public_at | String | The date and time the reporter agreed for the public disclosure.Formatted according to ISO 8601. | 
| HackerOne.Report.attributes.last_public_activity_at | String | The date and time that the most recent public activity was posted on the report.Formatted according to ISO 8601. | 
| HackerOne.Report.attributes.last_activity_at | String | The date and time that the most recent activity was posted on the report.Formatted according to ISO 8601. | 
| HackerOne.Report.attributes.source | String | A free-form string defining the source of the report for tracking purposes.For example, "detectify", "rapid7" or "jira". | 
| HackerOne.Report.attributes.timer_bounty_awarded_elapsed_time | Number | The total number of seconds that have elapsed between when the timer startedand when it stopped ticking. The timer does not take weekends into account. If the field is null and the corresponding miss_at field is set, it means the timer is still counting. | 
| HackerOne.Report.attributes.timer_bounty_awarded_miss_at | Date | The date and time the system expects the program to have awarded a bounty by. The field is null when the system does not expect the report to receive a bounty at the time. | 
| HackerOne.Report.attributes.timer_first_program_response_miss_at | Date | The date and time the system expects the program to have posted an initialpublic comment to the report by. | 
| HackerOne.Report.attributes.timer_first_program_response_elapsed_time | Number | The total number of seconds that have elapsed between when the timer startedand when it stopped ticking. The timer does not take weekends into account. If the field is null and the corresponding miss_at field is set, it means the timer is still counting. | 
| HackerOne.Report.attributes.timer_report_resolved_miss_at | Date | The date and time the system expects the program to have closed the report by.The field is null when the report seems blocked by the reporter. | 
| HackerOne.Report.attributes.timer_report_resolved_elapsed_time | Number | The total number of seconds that have elapsed between when the timer startedand when it stopped ticking. The timer does not take weekends into account. If the  field is null and the corresponding miss_at field is set, it means the timer is still counting. | 
| HackerOne.Report.attributes.timer_report_triage_miss_at | Date | The date and time the system expects the program to have triaged the report by. The  field is null when the system does not expect the report to be triaged at the time. | 
| HackerOne.Report.attributes.timer_report_triage_elapsed_time | Number | The total number of seconds that have elapsed between when the timer startedand when it stopped ticking. The timer does not take weekends into account. If the field is null and the corresponding miss_at field is set, it means the timer is still counting. | 
| HackerOne.Report.relationships.reporter.data.id | String | The unique ID of the reporter. | 
| HackerOne.Report.relationships.reporter.data.type | String | The type of the object of HackerOne. | 
| HackerOne.Report.relationships.reporter.data.attributes.username | String | The username of the reporter. | 
| HackerOne.Report.relationships.reporter.data.attributes.name | String | The name of the reporter. | 
| HackerOne.Report.data.relationships.reporter.data.attributes.disabled | Boolean | Indicates if the reporter is disabled. | 
| HackerOne.Report.data.relationships.reporter.data.attributes.created_at | String | The date and time the object was created. Formatted accordingto ISO 8601. | 
| HackerOne.Report.data.relationships.reporter.data.attributes.profile_picture.62x62 | String | URL of the profile photo of a reporter of size 62x62. | 
| HackerOne.Report.data.relationships.reporter.data.attributes.profile_picture.82x82 | String | URL of the profile photo of a reporter of size 82x82. | 
| HackerOne.Report.data.relationships.reporter.data.attributes.profile_picture.110x110 | String | URL of the profile photo of a reporter of size 110x110. | 
| HackerOne.Report.data.relationships.reporter.data.attributes.profile_picture.260x260 | String | URL of the profile photo of a reporter of size 260x260. | 
| HackerOne.Report.data.relationships.reporter.data.attributes.bio | String | The reporter's biography, as provided by the reporter. | 
| HackerOne.Report.data.relationships.reporter.data.attributes.reputation | Number | The reputation of the reporter. | 
| HackerOne.Report.data.relationships.reporter.data.attributes.signal | Number | The signal of the reporter. This number ranges from -10 to 7. The closer to 7, the higher the average submission quality of the reporter. | 
| HackerOne.Report.data.relationships.reporter.data.attributes.impact | Number | The impact of the reporter. This number ranges from 0 to 50. The closer to 50,the higher the average severity of the reporter's reports is. | 
| HackerOne.Report.data.relationships.reporter.data.attributes.website | String | The reporter's website, as provided by the reporter. | 
| HackerOne.Report.data.relationships.reporter.data.attributes.location | String | The reporter's location, as provided by the reporter. | 
| HackerOne.Report.data.relationships.reporter.data.attributes.hackerone_triager | Boolean | Indicates if the reporter is a hackerone triager. | 
| HackerOne.Report.data.relationships.program.data.id | String | The unique ID of the program. | 
| HackerOne.Report.data.relationships.program.data.type | String | The type of the object of HackerOne. | 
| HackerOne.Report.data.relationships.program.data.attributes.handle | String | The handle of the program. | 
| HackerOne.Report.data.relationships.program.data.attributes.created_at | String | The date and time the object was created. Formatted according to ISO 8601. | 
| HackerOne.Report.data.relationships.program.data.attributes.updated_at | String | The date and time the object was updated. Formatted according to ISO 8601. | 
| HackerOne.Report.data.relationships.severity.data.id | String | The unique ID of the severity. | 
| HackerOne.Report.data.relationships.severity.data.type | String | The type of the severity of HackerOne. | 
| HackerOne.Report.data.relationships.severity.data.attributes.rating | String | The qualitative rating of the severity. | 
| HackerOne.Report.data.relationships.severity.data.attributes.author_type | String | The involved party that provided the severity. | 
| HackerOne.Report.data.relationships.severity.data.attributes.user_id | Number | The unique id of the user who created the object. | 
| HackerOne.Report.data.relationships.severity.data.attributes.created_at | String | The date and time the object was created. Formatted according to ISO 8601. | 
| HackerOne.Report.data.relationships.severity.data.attributes.score | Number | The vulnerability score calculated from the Common Vulnerability Scoring System \(CVSS\). | 
| HackerOne.Report.data.relationships.severity.data.attributes.attack_complexity | String | A CVSS metric that describes the conditions beyond the attacker's control that must exist in order to exploit the vulnerability. | 
| HackerOne.Report.data.relationships.severity.data.attributes.attack_vector | String | A CVSS metric that reflects the context by which vulnerability exploitation is possible. | 
| HackerOne.Report.data.relationships.severity.data.attributes.availability | String | A CVSS metric that measures the availability of the impacted component resulting from a successfully exploited vulnerability. | 
| HackerOne.Report.data.relationships.severity.data.attributes.confidentiality | String | A CVSS metric that measures the impact to the confidentiality of the information resources managed by a software component due to a successfully exploited vulnerability. | 
| HackerOne.Report.data.relationships.severity.data.attributes.integrity | String | A CVSS metric that measures the impact to the integrity of a successfully exploited vulnerability. | 
| HackerOne.Report.data.relationships.severity.data.attributes.privileges_required | String | A CVSS metric that describes the level of privileges an attacker must possess beforesuccessfully exploiting the vulnerability. | 
| HackerOne.Report.data.relationships.severity.data.attributes.user_interaction | String | A CVSS metric that captures the requirement for a user, other than the attacker, to participate in the successful compromise of the vulnerability component. | 
| HackerOne.Report.data.relationships.severity.data.attributes.scope | String | A CVSS metric that determines if a successful attack impacts a component other than the vulnerable component. | 
| HackerOne.Report.data.relationships.weakness.data.id | String | The unique ID of the weakness. | 
| HackerOne.Report.data.relationships.weakness.data.type | String | The type of the object of HackerOne. | 
| HackerOne.Report.data.relationships.weakness.data.attributes.name | String | The name of the weakness. | 
| HackerOne.Report.data.relationships.weakness.data.attributes.description | String | The raw description of the weakness. | 
| HackerOne.Report.data.relationships.weakness.data.attributes.external_id | String | The weakness' external reference to CWE or CAPEC. | 
| HackerOne.Report.data.relationships.weakness.data.attributes.created_at | String | The date and time the object was created. Formatted according to ISO 8601. | 
| HackerOne.Report.data.relationships.custom_field_values.data.id | String | The unique ID of the custom field value. | 
| HackerOne.Report.data.relationships.custom_field_values.data.type | String | The type of the object of HackerOne. | 
| HackerOne.Report.data.relationships.custom_field_values.data.attributes.value | String | The attribute's value. | 
| HackerOne.Report.data.relationships.custom_field_values.data.attributes.created_at | String | The date and time the object was created. Formatted according to ISO 8601. | 
| HackerOne.Report.data.relationships.custom_field_values.data.attributes.updated_at | String | The date and time the object was updated. Formatted according to ISO 8601. | 
| HackerOne.Report.data.relationships.custom_field_values.data.relationships.custom_field_attribute.data.id | String | The unique ID of the custom field attribute. | 
| HackerOne.Report.data.relationships.custom_field_values.data.relationships.custom_field_attribute.data.type | String | The type of the object of HackerOne. | 
| HackerOne.Report.data.relationships.custom_field_values.data.relationships.custom_field_attribute.data.attributes.field_type | String | The type of custom field. | 
| HackerOne.Report.data.relationships.custom_field_values.data.relationships.custom_field_attribute.data.attributes.label | String | The attribute's label. | 
| HackerOne.Report.data.relationships.custom_field_values.data.relationships.custom_field_attribute.data.attributes.internal | Boolean | Internal or public custom field. | 
| HackerOne.Report.data.relationships.custom_field_values.data.relationships.custom_field_attribute.data.attributes.required | Boolean | Whether the field is required or not. | 
| HackerOne.Report.data.relationships.custom_field_values.data.relationships.custom_field_attribute.data.attributes.error_message | String | A custom error message when the regex validation fails. | 
| HackerOne.Report.data.relationships.custom_field_values.data.relationships.custom_field_attribute.data.attributes.helper_text | String | The helper text for custom_field_attribute. | 
| HackerOne.Report.data.relationships.custom_field_values.data.relationships.custom_field_attribute.data.attributes.configuration | String | An optional configuration for the attribute's type. | 
| HackerOne.Report.data.relationships.custom_field_values.data.relationships.custom_field_attribute.data.attributes.checkbox_text | String | The text shown with a checkbox field. | 
| HackerOne.Report.data.relationships.custom_field_values.data.relationships.custom_field_attribute.data.attributes.regex | String | A regex used to validate the input for a text field. | 
| HackerOne.Report.data.relationships.custom_field_values.data.relationships.custom_field_attribute.data.attributes.created_at | String | The date and time the object was created. Formatted according to ISO 8601. | 
| HackerOne.Report.data.relationships.custom_field_values.data.relationships.custom_field_attribute.data.attributes.updated_at | String | The date and time the object was updated. Formatted according to ISO 8601. | 
| HackerOne.Report.data.relationships.custom_field_values.data.relationships.custom_field_attribute.data.attributes.archived_at | String | The date and time the object was archived. Formatted according to ISO 8601. | 
| HackerOne.Report.data.relationships.assignee.data.id | String | The unique ID of the user. | 
| HackerOne.Report.data.relationships.assignee.data.type | String | The type of the object of HackerOne. | 
| HackerOne.Report.data.relationships.assignee.data.attributes.name | Unknown | The name of the assignee. | 
| HackerOne.Report.data.relationships.assignee.data.attributes.created_at | String | The date and time the object was created. Formatted according to ISO 8601. | 
| HackerOne.Report.data.relationships.assignee.data.attributes.permissions | String | The permissions of the group/user. Possible values are reward_management,program_management, user_management, and report_management. | 
| HackerOne.Report.data.relationships.assignee.data.attributes.username | String | The username of the assignee. | 
| HackerOne.Report.data.relationships.assignee.data.attributes.disabled | Boolean | Indicates if the assignee is disabled. | 
| HackerOne.Report.data.relationships.assignee.data.attributes.profile_picture.62x62 | String | URL of the profile photo of the assignee of size 62x62. | 
| HackerOne.Report.data.relationships.assignee.data.attributes.profile_picture.82x82 | String | URL of the profile photo of the assignee of size 82x82. | 
| HackerOne.Report.data.relationships.assignee.data.attributes.profile_picture.110x110 | String | URL of the profile photo of the assignee of size 110x110. | 
| HackerOne.Report.data.relationships.assignee.data.attributes.profile_picture.260x260 | String | URL of the profile photo of the assignee of size 260x260. | 
| HackerOne.Report.data.relationships.assignee.data.attributes.signal | Number | The signal of the assignee. The number ranges from -10 to 7. The closer to 7, the higher the average submission quality of the user. | 
| HackerOne.Report.data.relationships.assignee.data.attributes.impact | Number | The impact of the assignee. This number ranges from 0 to 50. The closer to 50, the higher the average severity of the user's reports is. | 
| HackerOne.Report.data.relationships.assignee.data.attributes.reputation | Number | The reputation of the assignee. | 
| HackerOne.Report.data.relationships.assignee.data.attributes.bio | String | The assignee's biography, as provided by the assignee. | 
| HackerOne.Report.data.relationships.assignee.data.attributes.website | String | The assignee's website, as provided by the assignee. | 
| HackerOne.Report.data.relationships.assignee.data.attributes.location | String | The assignee's location, as provided by the assignee. | 
| HackerOne.Report.data.relationships.assignee.data.attributes.hackerone_triager | Boolean | Indicates if the assignee is a hackerone triager. | 
| HackerOne.Report.data.relationships.structured_scope.data.id | String | The unique ID of the scope. | 
| HackerOne.Report.data.relationships.structured_scope.data.type | String | The type of the HackerOne object. | 
| HackerOne.Report.data.relationships.structured_scope.data.attributes.asset_type | String | The type of the asset. | 
| HackerOne.Report.data.relationships.structured_scope.data.attributes.asset_identifier | String | The identifier of the asset. | 
| HackerOne.Report.data.relationships.structured_scope.data.attributes.eligible_for_bounty | Boolean | If the asset is eligible for a bounty. | 
| HackerOne.Report.data.relationships.structured_scope.data.attributes.eligible_for_submission | Boolean | If the asset is eligible for a submission. | 
| HackerOne.Report.data.relationships.structured_scope.data.attributes.instruction | String | The raw instruction of the asset provided by the program. | 
| HackerOne.Report.data.relationships.structured_scope.data.attributes.max_severity | String | The qualitative rating of the maximum severity allowed on this asset. | 
| HackerOne.Report.data.relationships.structured_scope.data.attributes.created_at | Date | The date and time the object was created. Formatted according to ISO 8601. | 
| HackerOne.Report.data.relationships.structured_scope.data.attributes.updated_at | Date | The date and time the object was updated. Formatted according to ISO 8601. | 
| HackerOne.Report.data.relationships.structured_scope.data.attributes.reference | String | The customer defined reference identifier or tag of the asset. | 
| HackerOne.Report.data.relationships.bounties.data.id | String | The unique ID of the bounty. | 
| HackerOne.Report.data.relationships.bounties.data.type | String | The type of the HackerOne object. | 
| HackerOne.Report.data.relationships.bounties.data.attributes.created_at | Date | The date and time the object was created. Formatted according to ISO 8601. | 
| HackerOne.Report.data.relationships.bounties.data.attributes.amount | String | Amount in USD. | 
| HackerOne.Report.data.relationships.bounties.data.attributes.bonus_amount | String | Bonus amount in USD. | 
| HackerOne.Report.data.relationships.bounties.data.attributes.awarded_amount | String | Amount in awarded currency. | 
| HackerOne.Report.data.relationships.bounties.data.attributes.awarded_bonus_amount | String | Bonus amount in awarded currency. | 
| HackerOne.Report.data.relationships.bounties.data.attributes.awarded_currency | String | The currency used to award the bounty and bonus. | 


#### Command Example
```!hackerone-report-list program_handle=checker_program_h1b```

#### Context Example
```json
{
    "HackerOne": {
        "Report": {
            "attributes": {
                "bounty_awarded_at": "2021-09-01T10:04:25.102Z",
                "created_at": "2021-08-09T13:41:38.039Z",
                "first_program_activity_at": "2021-08-10T06:25:24.792Z",
                "last_activity_at": "2021-09-01T10:04:25.203Z",
                "last_program_activity_at": "2021-09-01T10:04:25.102Z",
                "last_public_activity_at": "2021-09-01T10:04:25.203Z",
                "last_reporter_activity_at": "2021-09-01T10:04:25.203Z",
                "state": "new",
                "timer_bounty_awarded_elapsed_time": 1455751,
                "timer_first_program_response_elapsed_time": 60226,
                "title": "Demo report: XSS in checker_program H1B home page",
                "vulnerability_information": "In some ***fantasy world***, the home page of checker_program H1B is vulnerable to an *imaginary* Cross-Site Scripting attack.\n\n1. Visit home page of checker_program H1B\n2. Open the browser's javascript console\n3. Type `alert(/xss!/)` and press enter\n4. Profit!\n\n## Impact\n\nIn our fantasy world, exploiting this vulnerability allows us to run an external script on your website that for example steals the cookies of the users that's facing the XSS and thus gaining access to the account of the victim."
            },
            "id": "1295856",
            "relationships": {
                "assignee": {
                    "data": {
                        "attributes": {
                            "created_at": "2021-08-02T09:27:56.324Z",
                            "disabled": false,
                            "hackerone_triager": false,
                            "name": "Jahnvi",
                            "profile_picture": {
                                "110x110": "/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png",
                                "260x260": "/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png",
                                "62x62": "/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png",
                                "82x82": "/assets/avatars/default-71a302d706457f3d3a31eb30fa3e73e6cf0b1d677b8fa218eaeaffd67ae97918.png"
                            },
                            "username": "jahnvi_crest"
                        },
                        "id": "1878386",
                        "type": "user"
                    }
                },
                "bounties": {
                    "data": [
                        {
                            "attributes": {
                                "amount": "100.00",
                                "awarded_amount": "100.00",
                                "awarded_bonus_amount": "0.00",
                                "awarded_currency": "USD",
                                "bonus_amount": "0.00",
                                "created_at": "2021-09-01T10:04:25.093Z",
                                "relationships": {
                                    "report": {
                                        "data": {
                                            "attributes": {
                                                "bounty_awarded_at": "2021-09-01T10:04:25.102Z",
                                                "created_at": "2021-08-09T13:41:38.039Z",
                                                "first_program_activity_at": "2021-08-10T06:25:24.792Z",
                                                "last_activity_at": "2021-09-01T10:04:25.203Z",
                                                "last_program_activity_at": "2021-09-01T10:04:25.102Z",
                                                "last_public_activity_at": "2021-09-01T10:04:25.203Z",
                                                "last_reporter_activity_at": "2021-09-01T10:04:25.203Z",
                                                "state": "new",
                                                "timer_bounty_awarded_elapsed_time": 1455751,
                                                "timer_first_program_response_elapsed_time": 60226,
                                                "title": "Demo report: XSS in checker_program H1B home page",
                                                "vulnerability_information": "In some ***fantasy world***, the home page of checker_program H1B is vulnerable to an *imaginary* Cross-Site Scripting attack.\n\n1. Visit home page of checker_program H1B\n2. Open the browser's javascript console\n3. Type `alert(/xss!/)` and press enter\n4. Profit!\n\n## Impact\n\nIn our fantasy world, exploiting this vulnerability allows us to run an external script on your website that for example steals the cookies of the users that's facing the XSS and thus gaining access to the account of the victim."
                                            },
                                            "id": "1295856",
                                            "type": "report"
                                        }
                                    }
                                }
                            },
                            "id": "331781",
                            "type": "bounty"
                        }
                    ]
                },
                "program": {
                    "data": {
                        "attributes": {
                            "created_at": "2021-08-09T13:41:35.764Z",
                            "handle": "checker_program_h1b",
                            "updated_at": "2021-08-10T09:29:56.984Z"
                        },
                        "id": "53996",
                        "type": "program"
                    }
                },
                "reporter": {
                    "data": {
                        "attributes": {
                            "created_at": "2014-03-17T20:14:25.383Z",
                            "disabled": false,
                            "hackerone_triager": false,
                            "location": "demo@example.com",
                            "name": "Demo Hacker",
                            "profile_picture": {
                                "110x110": "https://profile-photos.hackerone-user-content.com/variants/000/003/683/34dc17c69760632eba8908c6bc708eb7a20edee3_original.png/752d2b30dee362362a0bae9136e023e297ab1b5d752f5f982c8d27b3c2e1b14d",
                                "260x260": "https://profile-photos.hackerone-user-content.com/variants/000/003/683/34dc17c69760632eba8908c6bc708eb7a20edee3_original.png/5050d9689b90aee3f5bcd28e0e44e43067b7f21994f12447c87bef07e5a33711",
                                "62x62": "https://profile-photos.hackerone-user-content.com/variants/000/003/683/34dc17c69760632eba8908c6bc708eb7a20edee3_original.png/b5f65e84b294d95ac0e5fb3698d567882eeab915bc7725c4748f6d620a9f6f32",
                                "82x82": "https://profile-photos.hackerone-user-content.com/variants/000/003/683/34dc17c69760632eba8908c6bc708eb7a20edee3_original.png/89a94cba69dc9474b9dcbe84db52487a172581abe654290fb10ed6a4585414a9"
                            },
                            "reputation": 100,
                            "username": "demo-hacker"
                        },
                        "id": "3683",
                        "type": "user"
                    }
                },
                "severity": {
                    "data": {
                        "attributes": {
                            "attack_complexity": "high",
                            "attack_vector": "adjacent",
                            "author_type": "Team",
                            "availability": "low",
                            "confidentiality": "none",
                            "created_at": "2021-08-10T06:26:14.670Z",
                            "integrity": "low",
                            "privileges_required": "none",
                            "rating": "low",
                            "scope": "unchanged",
                            "score": 3.7,
                            "user_id": 1878386,
                            "user_interaction": "required"
                        },
                        "id": "1185908",
                        "type": "severity"
                    }
                },
                "structured_scope": {
                    "data": {
                        "attributes": {
                            "asset_identifier": "com.sec.my_app",
                            "asset_type": "GOOGLE_PLAY_APP_ID",
                            "created_at": "2021-08-09T13:48:56.007Z",
                            "eligible_for_bounty": true,
                            "eligible_for_submission": true,
                            "max_severity": "critical",
                            "updated_at": "2021-08-09T13:48:56.007Z"
                        },
                        "id": "77411",
                        "type": "structured-scope"
                    }
                },
                "weakness": {
                    "data": {
                        "attributes": {
                            "created_at": "2018-05-14T20:48:46.308Z",
                            "description": "The software allocates a reusable resource or group of resources on behalf of an actor without imposing any restrictions on how many resources can be allocated, in violation of the intended security policy for that actor.",
                            "external_id": "cwe-770",
                            "name": "Allocation of Resources Without Limits or Throttling"
                        },
                        "id": "120",
                        "type": "weakness"
                    }
                }
            },
            "type": "report"
        }
    }
}
```

#### Human Readable Output

>### Report(s)
>|Report ID|Reporter Username|Title|State|Created At|Vulnerability Information|
>|---|---|---|---|---|---|
>| 1295856 | demo-hacker | Demo report: XSS in checker_program H1B home page | new | 2021-08-09T13:41:38.039Z | In some ***fantasy world***, the home page of checker_program H1B is vulnerable to an *imaginary* Cross-Site Scripting attack.<br/><br/>1. Visit home page of checker_program H1B<br/>2. Open the browser's javascript console<br/>3. Type `alert(/xss!/)` and press enter<br/>4. Profit!<br/><br/>## Impact<br/><br/>In our fantasy world, exploiting this vulnerability allows us to run an external script on your website that for example steals the cookies of the users that's facing the XSS and thus gaining access to the account of the victim. |


### hackerone-program-list
***
Retrieves detailed information of all the programs that the user is a member of.


#### Base Command

`hackerone-program-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_size | The number of programs to retrieve per page.<br/>Note: Possible values are between 1 and 100. Default is 50. | Optional | 
| page_number | Page number to retrieve the programs from the specified page. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HackerOne.Program.id | String | The unique ID of the program. | 
| HackerOne.Program.type | String | The type of the object of HackerOne. | 
| HackerOne.Program.attributes.handle | String | The handle of the program. | 
| HackerOne.Program.attributes.policy | String | The policy of the program. | 
| HackerOne.Program.attributes.created_at | Date | The date and time the object was created. Formatted according to ISO 8601. | 
| HackerOne.Program.attributes.updated_at | Date | The date and time the object was updated. Formatted according to ISO 8601. | 


#### Command Example
```!hackerone-program-list page_size=1```

#### Context Example
```json
{
    "HackerOne": {
        "Program": {
            "attributes": {
                "created_at": "2021-08-09T13:39:20.342Z",
                "handle": "something_h1b",
                "policy": "# What we are looking for\r\nWe want to proactively discover and remediate security vulnerabilities on our digital assets\r\n\r\nThe vulnerabilities identified in the HackerOne reports will be classified by the degree of risk as well as the impact they present to the host system, this includes the amount and type of data exposed, privilege level obtained, the proportion of systems or users affected.\r\n\r\n# What is a Bug Bounty Program?\r\nsomething\u2019s Bug Bounty Program (BBP) is an initiative driven and managed by the something Information Security team. \r\n\r\n* Security researchers are encouraged to report any behavior impacting the information security posture of something\u2019 products and services. If you are performing research, please use your own accounts and do not interact with other people\u2019s accounts or data.\r\n* Document your findings thoroughly, providing steps to reproduce and send your report to us. Reports with complete vulnerability details, including screenshots or video, are essential for a quick response. If the report is not detailed enough to reproduce the issue, the issue will not be eligible for a reward.\r\n  *Reference HackerOne guidance on writing quality reports:\r\n   * https://docs.hackerone.com/hackers/quality-reports.html \r\n   * https://www.hacker101.com/sessions/good_reports\r\n\r\n* We will contact you to confirm that we\u2019ve received your report and trace your steps to reproduce your research.\r\n* We will work with the affected teams to validate the report.\r\n* We will issue bounty awards for eligible findings. To be eligible for rewards, reports must comply with all parts of this policy and you must be the first to report the issue to us. You must be 18 or older to be eligible for an award.\r\n* We will notify you of remediation and may reach out for questions or clarification. You must be available to provide additional information if needed by us to reproduce and investigate the report.\r\n\r\n\r\n# Response Targets\r\nWe will make a best effort to meet the following response targets for hackers participating in our program:\r\n\r\n* Time to first response (from report submit) - 1 business days\r\n* Time to triage (from report submit) - 2 business days \r\n* Time to bounty (from triage) - 10 business days\r\n\r\nWe\u2019ll try to keep you informed about our progress throughout the process.\r\n\r\n#  Program Rules\r\n* Do not try to further pivot into the network by using a vulnerability. The rules around Remote Code Execution (RCE), SQL Injection (SQLi), and FileUpload vulnerabilities are listed below.\r\n* Do not try to exploit service providers we use, prohibited actions include, but are not limited to bruteforcing login credentials of Domain Registrars, DNS Hosting Companies, Email Providers and/or others. The Firm does not authorize you to perform any actions to any property/system/service/data not listed below.\r\n* If you encounter Personally Identifiable Information (PII) contact us immediately. Do not proceed with access and immediately purge any local information, if applicable.\r\n* Please limit any automated scanning to 60 requests per second. Aggressive testing that causes service degradation will be grounds for removal from the program.\r\n\r\n* Submit one vulnerability per- report, unless you need to chain vulnerabilities to provide impact.\r\n* When duplicates occur, we only award the first report that was received (provided that it can be fully reproduced).\r\n* Multiple vulnerabilities caused by one underlying issue will be awarded one bounty.\r\n* Social engineering (e.g. phishing, vishing, smishing) is prohibited.\r\n* Make a good faith effort to avoid privacy violations, destruction of data, and interruption or degradation of our service. Only interact with accounts you own or with the explicit permission of the account holder.\r\n\r\n# Disclosure Policy\r\n* As this is a private program, please do not discuss this program or any vulnerabilities (even resolved ones) outside of the program without express consent from the organization.\r\n* Follow HackerOne's [disclosure guidelines](https://www.hackerone.com/disclosure-guidelines).\r\n\r\n\r\n# How To Create Accounts\r\n* Go to our Website\r\n* Register \r\n* use @hackerone.com email address\r\n* Only use accounts you're authorised to access\r\n\r\n# Rewards\r\nOur rewards are based on severity per the Common Vulnerability Scoring Standard (CVSS). Please note these are general guidelines, and that reward decisions are up to the discretion of something.\r\n\r\n#Out of scope vulnerabilities\r\n\r\n\r\n***Note: 0-day vulnerabilities may be reported 30 days after initial publication. We have a team dedicated to tracking these issues; hosts identified by this team and internally ticketed will not be eligible for bounty.***\r\n\r\nThe following issues are considered out of scope:\r\n \r\n When reporting vulnerabilities, please consider (1) attack scenario / exploitability, and (2) security impact of the bug. The following issues are considered out of scope:\r\n\r\n* Disruption of our service (DoS, DDoS).\r\n* PII - do not collect any personally identifiable information - including credit card information, addresses and phone numbers from other customers\r\n* Reports from automated tools or scans\r\n* Social engineering of employees or contractors\r\n* For the time being we are making all vulnerabilities in Flash files out of scope\r\n* Reports affecting outdated browsers\r\n* Known vulnerabilities on deprecated assets not currently covered by CloudFlare.\r\n* Missing security best practices and controls (rate-limiting/throttling, lack of CSRF protection, lack of security headers, missing flags on cookies, descriptive errors, server/technology disclosure - without clear and working exploit)\r\n* Lack of crossdomain.xml, p3p.xml, robots.txt or any other policy files and/or wildcard presence/misconfigurations in these\r\n* Use of a known-vulnerable libraries or frameworks - for example an outdated JQuery or AngularJS (without clear and working exploit)\r\n* Self-exploitation (cookie reuse, self cookie-bomb, self denial-of-service etc.)\r\n* Self Cross-site Scripting vulnerabilities without evidence on how the vulnerability can be used to attack another user\r\n* Lack of HTTPS\r\n* Reports about insecure SSL / TLS configuration\r\n* Password complexityrequirements, account/email enumeration, or any report that discusses how you can learn whether a given username or email address is easy to guess\r\n* Presence/Lack of autocomplete attribute on web forms/password managers\r\n* Server Banner Disclosure/Technology used Disclosure\r\n* Full Path Disclosure\r\n* IP Address Disclosure\r\n* CSRF on logout or insignificant functionalities\r\n* Publicly accessible login panels\r\n* Clickjacking\r\n* CSS Injection attacks (Unless it gives you ability to read anti-CSRF tokens or other sensitive information)\r\n* Tabnabbing\r\n* Host Header Injection (Unless it givesyou access to interim proxies)\r\n* Cache Poisoning\r\n* Reflective File Download\r\n* Cookie scoped to parent domain or anything related to the path misconfiguration and improperly scoped\r\n* Private IP/Hostname disclosures or real IP disclosures for services using CDN\r\n* Open ports which do not lead directly to a vulnerability\r\n* Weak Certificate Hash Algorithm\r\n* Any physical/wireless attempt against our property or data centers\r\n\r\n# Safe Harbor \r\nThis policy is designed to be compatible with common vulnerability disclosure good practice. It does not give you permission to act in any manner that is inconsistent with the law, or which might cause us to be in breach of any of its legal obligations, including but not limited to:\r\n\r\n* The General Data Protection Regulation 2016/679 (GDPR) andthe Data Protection Act 2018\r\n\r\nWe affirm that we will not seek prosecution of any security researcher who reports any security vulnerability on a service or system, where the researcher has acted in good faith and in accordance with this disclosure policy.\r\n\r\nsomething cannot authorize any activity on third-party products or guarantee they won\u2019t pursue legal action against you. We aren\u2019t responsible for your liability from actions performed on third parties.\r\n\r\nThank you for helping keep us and our users safe!\r\n\n",
                "updated_at": "2021-08-10T09:29:56.853Z"
            },
            "id": "53994",
            "type": "program"
        }
    }
}
```

#### Human Readable Output

>### Program(s)
>|Program ID|Handle|Created At|Updated At|
>|---|---|---|---|
>| 53994 | something_h1b | 2021-08-09T13:39:20.342Z | 2021-08-10T09:29:56.853Z |

