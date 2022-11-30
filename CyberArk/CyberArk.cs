/******************************************************************************
 * Name: CyberArk
 * Type: DLL
 * Author: Ron Hagerman
 * Company: Recreational Equipment Inc. (https://wwww.rei.com)
 * Purpose: A collection of API calls to any instance of CyberArk to autmate
 * tasks and retrieve report data, etc.
 ******************************************************************************/


using System;
using System.Collections.Generic;
using RestSharp;

namespace CyberArk
{
    public class clsCyberArk
    {
        /********************************
         * Token functions
         * *****************************/

        public static string Token(string username, string passwd, string pvwa, string authMethod)
        {
            Globals g = new Globals();

            var client = new RestClient($"https://{pvwa}/PasswordVault/api/auth/{authMethod}/Logon");
            client.Timeout = -1;
            var request = new RestRequest(Method.POST);
            request.AddHeader("Content-Type", "application/json");

            var body = "{";
            body += $" {g.NewLine} \"Username\": \"{username}\", {g.NewLine} \"Password\": \"{passwd}\",{g.NewLine} \"concurrentSessions\": \"true\" {g.NewLine}";
            body += "}";

            request.AddParameter("application/json", body, ParameterType.RequestBody);

            IRestResponse response = client.Execute(request);

            if (response.StatusCode == (System.Net.HttpStatusCode)200)
                return response.Content;
            else
            {
                return "Logon Error";
            }
        }

        public static string DisposeToken(string token, string pvwa)
        {
            var client = new RestClient($"https://{pvwa}/PasswordVault/api/auth/Logoff");
            client.Timeout = -1;
            var request = new RestRequest(Method.POST);
            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");
            IRestResponse response = client.Execute(request);

            return response.Content;
        }

        /********************************
         * Account functions
         * *****************************/
        public static string GetAccount(string token, string safename, string pvwa)
        {
            var client = new RestClient($"https://{pvwa}/PasswordVault/api/Accounts?search=&searchType=contains&filter=safeName eq {safename}");
            client.Timeout = -1;
            var request = new RestRequest(Method.GET);
            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");
            IRestResponse response = client.Execute(request);

            return response.Content;
        }

        public static string GetAccounts(string token, string pvwa, string offset, string limit)
        {
            var client = new RestClient($"https://{pvwa}/PasswordVault/api/Accounts?offset={offset}&limit={limit}");
            client.Timeout = -1;
            var request = new RestRequest(Method.GET);
            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");
            IRestResponse response = client.Execute(request);

            return response.Content;
        }

        public static string ListAccounts(string token, string pvwa)
        {

            var client = new RestClient($"https://{pvwa}/PasswordVault/api/Accounts?search=&searchType=contains&sort=UserName");
            client.Timeout = -1;
            var request = new RestRequest(Method.GET);
            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");
            IRestResponse response = client.Execute(request);

            return response.Content;
        }

        public static string GetPending(string token, string pvwa)
        {

            RestClient client = new RestClient($"https://{pvwa}/PasswordVault/api/DiscoveredAccounts?limit=1000");
            client.Timeout = -1;
            RestRequest request = new RestRequest(Method.GET);
            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");
            IRestResponse response = client.Execute(request);

            return response.Content;
        }

        public static string GetPendingDetails(string token, string pvwa, string id)
        {

            RestClient client = new RestClient($"https://{pvwa}/PasswordVault/api/DiscoveredAccounts/{id}");
            client.Timeout = -1;
            RestRequest request = new RestRequest(Method.GET);
            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");
            IRestResponse response = client.Execute(request);

            return response.Content;
        }

        public static string GetPending(string token, string pvwa, string offset)
        {

            RestClient client = new RestClient($"https://{pvwa}/PasswordVault/api/DiscoveredAccounts?limit=1000&offset={offset}");
            client.Timeout = -1;
            RestRequest request = new RestRequest(Method.GET);
            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");
            IRestResponse response = client.Execute(request);

            return response.Content;
        }

        public static string GetPending(string token, string pvwa, string limit, string offset)
        {

            RestClient client = new RestClient($"https://{pvwa}/PasswordVault/api/DiscoveredAccounts?limit={limit}&offset={offset}");
            client.Timeout = -1;
            RestRequest request = new RestRequest(Method.GET);
            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");
            IRestResponse response = client.Execute(request);

            return response.Content;
        }

        public static string Reconcile(string token, string AccountId, string pvwa)
        {
            string Url = $"https://{pvwa}/PasswordVault/API/Accounts/{AccountId}/Reconcile";

            var client = new RestClient(Url);
            client.Timeout = -1;
            var request = new RestRequest(Method.POST); client.Timeout = -1;

            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");
            IRestResponse response = client.Execute(request);


            return response.Content;
        }

        public static string GetExtended(string token, string pvwa, string acctId)
        {

            RestClient client = new RestClient($"https://{pvwa}/PasswordVault/api/ExtendedAccounts/{acctId}/overview");
            client.Timeout = -1;
            RestRequest request = new RestRequest(Method.GET);
            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");
            IRestResponse response = client.Execute(request);

            return response.Content;
        }

        public static string OnboardAccount(string token, string userName, string address, string platform, string safe, string logonDomain, string pvwa)
        {
            Globals g = new Globals();

            var client = new RestClient($"https://{pvwa}/PasswordVault/api/Accounts");
            client.Timeout = -1;
            var request = new RestRequest(Method.POST);
            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");

            var body = $"{{{g.NewLine}";
            body += $"\"name\": \"Operating System-{address}-{userName}\",{g.NewLine}";
            body += $"\"address\": \"{address}\",{g.NewLine}";
            body += $"\"userName\": \"{userName}\",{g.NewLine}";
            body += $"\"platformId\": \"{platform}\",{g.NewLine}";
            body += $"\"safeName\": \"{safe}\",{g.NewLine}";
            body += $"\"secretType\": \"password\",{g.NewLine}";
            body += $"\"secret\": \"\",{g.NewLine}";
            body += $"\"platformAccountProperties\": {{{g.NewLine}";
            body += $"\"LogonDomain\": \"{logonDomain}\"{g.NewLine}}},";
            body += $"\"SecretManagement\": {{{g.NewLine}";
            body += $"\"automaticManagementEnabled\": true{g.NewLine}}}{g.NewLine}}}";

            request.AddParameter("application/json", body, ParameterType.RequestBody);
            IRestResponse response = client.Execute(request);

            return response.Content;
        }

        /*******************************
         * Safe functions
         * ****************************/

        public static string CreateSafe(string token, string safeName, string managingCPM, string pvwa)
        {

            string NewLine = Environment.NewLine;

            var client = new RestClient($"https://{pvwa}/PasswordVault/api/Safes");
            client.Timeout = -1;
            var request = new RestRequest(Method.POST);
            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");

            var body = $"{{{NewLine}";
            body += $"\"SafeName\": \"{safeName}\",{NewLine}";
            body += $"\"Description\":\"\",{NewLine}";
            body += $"\"OLACEnabled\": false,{NewLine}";
            body += $"\"ManagingCPM\": \"{managingCPM}\",{NewLine}";
            body += $"\"NumberOfVersionsRetention\": null,{NewLine}";
            body += $"\"NumberOfDaysRetention\": 7,{NewLine}";
            body += $"\"AutoPurgeEnabled\": false,{NewLine}";
            body += $"\"Location\": \"\\\\\"{NewLine}";
            body += "}";

            request.AddParameter("application/json", body, ParameterType.RequestBody);
            IRestResponse response = client.Execute(request);

            return response.Content;
        }

        public static bool SafeExists(string token, string safe, string pvwa)
        {
            var client = new RestClient($"https://{pvwa}/PasswordVault/WebServices/PIMServices.svc/Safes?query={safe}");
            client.Timeout = -1;
            var request = new RestRequest(Method.GET);
            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");
            IRestResponse response = client.Execute(request);



            bool safeExists = response.Content.Contains("SearchSafesResult\":[]") ? false : true;

            return safeExists;

        }

        public static string GetSafes(string token, string pvwa, string offset, string limit)
        {
            limit = string.IsNullOrEmpty(limit) ? "100" : limit;
            offset = string.IsNullOrEmpty(offset) ? "0" : offset;

            var client = new RestClient($"https://{pvwa}/PasswordVault/api/Safes?offset={offset}&limit={limit}");
            client.Timeout = -1;
            var request = new RestRequest(Method.GET);
            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");
            IRestResponse response = client.Execute(request);


            return response.Content;
        }

        public static string GetSafes(string token, string pvwa, string offset)
        {
            var client = new RestClient($"https://{pvwa}/PasswordVault/api/Safes?offset={offset}");
            client.Timeout = -1;
            var request = new RestRequest(Method.GET);
            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");
            IRestResponse response = client.Execute(request);


            return response.Content;
        }

        public static string GetSafes(string token, string pvwa)
        {

            var client = new RestClient($"https://{pvwa}/PasswordVault/api/Safes");
            client.Timeout = -1;
            var request = new RestRequest(Method.GET);
            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");
            IRestResponse response = client.Execute(request);


            return response.Content;
        }

        public static string GetSafesV1(string token, string pvwa)
        {

            var client = new RestClient($"https://{pvwa}/PasswordVault/WebServices/PIMServices.svc/Safes");
            client.Timeout = -1;
            var request = new RestRequest(Method.GET);
            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");
            IRestResponse response = client.Execute(request);


            return response.Content;
        }

        public static string GetSafe(string token, string safe, string pvwa)
        {

            var client = new RestClient($"https://{pvwa}/PasswordVault/WebServices/PIMServices.svc/Safes?query={safe}");
            client.Timeout = -1;
            var request = new RestRequest(Method.GET);
            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");
            IRestResponse response = client.Execute(request);


            return response.Content;
        }

        public static string GetSafeDetails(string token, string safe, string pvwa)
        {

            var client = new RestClient($"https://{pvwa}/PasswordVault/API/Safes/{safe}");
            client.Timeout = -1;
            var request = new RestRequest(Method.GET);
            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");
            IRestResponse response = client.Execute(request);

            return response.Content;
        }

        public static string GetSafeMembers(string token, string safe, string pvwa)
        {

            var client = new RestClient($"https://{pvwa}/PasswordVault/WebServices/PIMServices.svc/Safes/{safe}/Members");
            client.Timeout = -1;
            var request = new RestRequest(Method.GET);
            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");
            IRestResponse response = client.Execute(request);

            return response.Content;
        }

        /*************************************************************
         * These functions will add or update various members to your safe
         * with a specific set of permissions. You can modify these
         * to fit your environment.
         * ***********************************************************/
        public static string AddPAMAdmins(string token, string safe, string pvwa)
        {
            Globals g = new Globals();

            if (safe == null || safe == string.Empty) return "Safe name is empty";

            Dictionary<string, string> perms = new Dictionary<string, string>();

            perms = Globals.PAMAdmins;

            string Uri = $"https://{pvwa}/PasswordVault/WebServices/PIMServices.svc/Safes/{safe}/Members";
            var client = new RestClient(Uri);
            client.Timeout = -1;
            var request = new RestRequest(Method.POST);
            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");

            var body = $"{{{g.NewLine}";
            body += $"\"member\": {{{g.NewLine}";
            body += $"\"MemberName\":\"PAMAdmins\",{g.NewLine}";
            body += $"\"SearchIn\":\"Vault\",{g.NewLine}";
            body += $"\"MembershipExpirationDate\":\"\",{g.NewLine}";
            body += $"\"Permissions\":{g.NewLine}";
            body += $"[{g.NewLine}";

            foreach (KeyValuePair<string, string> keyValues in perms)
            {
                body += $"{{\"Key\": \"{keyValues.Key}\", \"Value\": {keyValues.Value}{g.NewLine}";
            }

            body += $"]{g.NewLine}}}{g.NewLine}}}";

            request.AddParameter("application/json", body, ParameterType.RequestBody);
            IRestResponse response = client.Execute(request);

            return $"body:{g.NewLine}{body}{g.NewLine}Response:{g.NewLine}{response.Content}";
        }

        public static string AddVaultAdmins(string token, string safe, string pvwa)
        {
            Globals g = new Globals();

            if (safe == null || safe == string.Empty) return "Safe name is empty";

            Dictionary<string, string> perms = new Dictionary<string, string>();

            perms = Globals.VaultAdmins;

            string Uri = $"https://{pvwa}/PasswordVault/WebServices/PIMServices.svc/Safes/{safe}/Members";
            var client = new RestClient(Uri);
            client.Timeout = -1;
            var request = new RestRequest(Method.POST);
            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");

            var body = $"{{{g.NewLine}";
            body += $"\"member\": {{{g.NewLine}";
            body += $"\"MemberName\":\"Vault Admins\",{g.NewLine}";
            body += $"\"SearchIn\":\"Vault\",{g.NewLine}";
            body += $"\"MembershipExpirationDate\":\"\",{g.NewLine}";
            body += $"\"Permissions\":{g.NewLine}";
            body += $"[{g.NewLine}";

            foreach (KeyValuePair<string, string> keyValues in perms)
            {
                body += $"{{\"Key\": \"{keyValues.Key}\", \"Value\": {keyValues.Value}{g.NewLine}";
            }

            body += $"]{g.NewLine}}}{g.NewLine}}}";

            request.AddParameter("application/json", body, ParameterType.RequestBody);
            IRestResponse response = client.Execute(request);

            return $"body:{g.NewLine}{body}{g.NewLine}Response:{g.NewLine}{response.Content}";
        }

        public static string AddAdministrators(string token, string safe, string pvwa)
        {
            Globals g = new Globals();

            if (safe == null || safe == string.Empty) return "Safe name is empty";

            Dictionary<string, string> perms = new Dictionary<string, string>();

            perms = Globals.Administrators;

            string Uri = $"https://{pvwa}/PasswordVault/WebServices/PIMServices.svc/Safes/{safe}/Members";
            var client = new RestClient(Uri);
            client.Timeout = -1;
            var request = new RestRequest(Method.POST);
            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");

            var body = $"{{{g.NewLine}";
            body += $"\"member\": {{{g.NewLine}";
            body += $"\"MemberName\":\"Administrators\",{g.NewLine}";
            body += $"\"SearchIn\":\"Vault\",{g.NewLine}";
            body += $"\"MembershipExpirationDate\":\"\",{g.NewLine}";
            body += $"\"Permissions\":{g.NewLine}";
            body += $"[{g.NewLine}";

            foreach (KeyValuePair<string, string> keyValues in perms)
            {
                body += $"{{\"Key\": \"{keyValues.Key}\", \"Value\": {keyValues.Value}{g.NewLine}";
            }

            body += $"]{g.NewLine}}}{g.NewLine}}}";

            request.AddParameter("application/json", body, ParameterType.RequestBody);
            IRestResponse response = client.Execute(request);

            return $"body:{g.NewLine}{body}{g.NewLine}Response:{g.NewLine}{response.Content}";
        }

        public static string AddAllSafes(string token, string safe, string pvwa)
        {
            Globals g = new Globals();

            if (safe == null || safe == string.Empty) return "Safe name is empty";

            Dictionary<string, string> perms = new Dictionary<string, string>();

            perms = Globals.AllSafes;

            string Uri = $"https://{pvwa}/PasswordVault/WebServices/PIMServices.svc/Safes/{safe}/Members";
            var client = new RestClient(Uri);
            client.Timeout = -1;
            var request = new RestRequest(Method.POST);
            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");

            var body = $"{{{g.NewLine}";
            body += $"\"member\": {{{g.NewLine}";
            body += $"\"MemberName\":\"Safe-LISTALL_ZPER_SAFES\",{g.NewLine}";
            body += $"\"SearchIn\":\"Vault\",{g.NewLine}";
            body += $"\"MembershipExpirationDate\":\"\",{g.NewLine}";
            body += $"\"Permissions\":{g.NewLine}";
            body += $"[{g.NewLine}";

            foreach (KeyValuePair<string, string> keyValues in perms)
            {
                body += $"{{\"Key\": \"{keyValues.Key}\", \"Value\": {keyValues.Value}{g.NewLine}";
            }

            body += $"]{g.NewLine}}}{g.NewLine}}}";

            request.AddParameter("application/json", body, ParameterType.RequestBody);
            IRestResponse response = client.Execute(request);

            return $"body:{g.NewLine}{body}{g.NewLine}Response:{g.NewLine}{response.Content}";
        }

        public static string AddUser(string token, string safe, string user, string pvwa)
        {
            Globals g = new Globals();

            if (safe == null || safe == string.Empty) return "Safe name is empty";

            Dictionary<string, string> perms = new Dictionary<string, string>();

            perms = Globals.User;

            string Uri = $"https://{pvwa}/PasswordVault/WebServices/PIMServices.svc/Safes/{safe}/Members";
            var client = new RestClient(Uri);
            client.Timeout = -1;
            var request = new RestRequest(Method.POST);
            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");

            var body = $"{{{g.NewLine}";
            body += $"\"member\": {{{g.NewLine}";
            body += $"\"MemberName\":\"{user}\",{g.NewLine}";
            body += $"\"SearchIn\":\"REICORPNET\",{g.NewLine}";
            body += $"\"MembershipExpirationDate\":\"\",{g.NewLine}";
            body += $"\"Permissions\":{g.NewLine}";
            body += $"[{g.NewLine}";

            foreach (KeyValuePair<string, string> keyValues in perms)
            {
                body += $"{{\"Key\": \"{keyValues.Key}\", \"Value\": {keyValues.Value}{g.NewLine}";
            }

            body += $"]{g.NewLine}}}{g.NewLine}}}";

            request.AddParameter("application/json", body, ParameterType.RequestBody);
            IRestResponse response = client.Execute(request);

            return $"body:{g.NewLine}{body}{g.NewLine}Response:{g.NewLine}{response.Content}";
        }

        public static string UpdateUser(string token, string safe, string user, string pvwa)
        {
            Globals g = new Globals();

            if (safe == null || safe == string.Empty) return "Safe name is empty";

            Dictionary<string, string> perms = new Dictionary<string, string>();

            perms = Globals.User;

            string Uri = $"https://{pvwa}/PasswordVault//api/Safes/{safe}/Members/{user}";
            RestClient client = new RestClient(Uri)
            {
                Timeout = -1
            };
            var request = new RestRequest(Method.PUT);
            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");

            string body = $"{{{g.NewLine}";

            body += $"\"Permissions\": {{{g.NewLine}";

            foreach (KeyValuePair<string, string> keyValues in perms)
            {
                body += $"\"{keyValues.Key}\" : {keyValues.Value},{g.NewLine}";
            }

            body += $"}}{g.NewLine}}}";

            request.AddParameter("application/json", body, ParameterType.RequestBody);
            IRestResponse response = client.Execute(request);

            return $"body:{g.NewLine}{body.TrimEnd(',')}{g.NewLine}Response:{g.NewLine}{response.Content}";
        }

        /************************
         * User functions
         * *********************/
        public static string GetUsersExtended(string token, string pvwa, string offset, string limit)
        {
            var client = new RestClient($"https://{pvwa}/PasswordVault/api/Users?offset={offset}&limit={limit}&extendedDetails=true");
            client.Timeout = -1;
            var request = new RestRequest(Method.GET);
            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");
            IRestResponse response = client.Execute(request);


            return response.Content;
        }

        public static string GetUsers(string token, string pvwa, string offset, string limit)
        {
            var client = new RestClient($"https://{pvwa}/PasswordVault/api/Users?offset={offset}&limit={limit}");
            client.Timeout = -1;
            var request = new RestRequest(Method.GET);
            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");
            IRestResponse response = client.Execute(request);


            return response.Content;
        }

        public static string GetUsers(string token, string pvwa, string acctId)
        {
            var client = new RestClient($"https://{pvwa}/PasswordVault/api/Users/{acctId}");
            client.Timeout = -1;
            var request = new RestRequest(Method.GET);
            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");
            IRestResponse response = client.Execute(request);


            return response.Content;
        }

        /**************************
         * Platform Management
         * ***********************/

        public static string GetPlatforms(string token, string pvwa)
        {

            RestClient client = new RestClient($"https://{pvwa}/PasswordVault/api/platforms");
            client.Timeout = -1;
            RestRequest request = new RestRequest(Method.GET);
            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");
            IRestResponse response = client.Execute(request);

            return response.Content;
        }

        public static string GetPlatforms(string token, string pvwa, string name)
        {

            RestClient client = new RestClient($"https://{pvwa}/PasswordVault/api/platforms?platformName={name}");
            client.Timeout = -1;
            RestRequest request = new RestRequest(Method.GET);
            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");
            IRestResponse response = client.Execute(request);

            return response.Content;
        }

        //public static string GetPPlatforms(string token, string pvwa,string active)
        //{

        //    RestClient client = new RestClient($"https://{pvwa}/PasswordVault/api/platforms?active={active}");
        //    client.Timeout = -1;
        //    RestRequest request = new RestRequest(Method.GET);
        //    request.AddHeader("Authorization", token);
        //    request.AddHeader("Content-Type", "application/json");
        //    IRestResponse response = client.Execute(request);

        //    return response.Content;
        //}

        public static string GetPlatforms(string token, string pvwa, string active, string name)
        {

            RestClient client = new RestClient($"https://{pvwa}/PasswordVault/api/platforms?active={active}&platformName={name}");
            client.Timeout = -1;
            RestRequest request = new RestRequest(Method.GET);
            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");
            IRestResponse response = client.Execute(request);

            return response.Content;
        }
        public static string GetPlatfornDetails(string token, string pvwa, string platform)
        {
            var client = new RestClient($"https://{pvwa}/PasswordVault/api/platforms/{platform}");
            client.Timeout = -1;
            var request = new RestRequest(Method.GET);
            request.AddHeader("Authorization", token);
            request.AddHeader("Content-Type", "application/json");
            IRestResponse response = client.Execute(request);

            return response.Content;
        }

    }

    /********************
     * Global Variables
     * *****************/
    public class Globals
    {
        public string SafeName
        { get; set; }

        public string Description
        { get; set; }

        public string ManagingCPM
        { get; set; }

        public string Token
        { get; set; }

        public string MemberName
        { get; set; }

        public string SearchIn
        { get; set; }

        public bool LoggedOn
        { get; set; }
        public string PVWA
        { get; set; }

        public string OLACEnabled => "false";

        public string NumberOfVersionsRetention => "null";

        public string AutoPurgeEnabled => "false";

        public string Location => @"\\";

        public string NewLine => Environment.NewLine;

        /*********************************************************
         * You can add, remove or modify these to fit your 
         * environment.
         * *******************************************************/
        public static Dictionary<string, string> PAMAdmins
        {
            get
            {
                Dictionary<string, string> perms = new Dictionary<string, string>();

                perms.Add("UseAccounts", "true},");
                perms.Add("RetrieveAccounts", "true},");
                perms.Add("ListAccounts", "true},");
                perms.Add("AddAccounts", "true},");
                perms.Add("UpdateAccountContent", "true},");
                perms.Add("UpdateAccountProperties", "true},");
                perms.Add("InitiateCPMAccountManagementOperations", "true},");
                perms.Add("SpecifyNextAccountContent", "true},");
                perms.Add("RenameAccounts", "true},");
                perms.Add("DeleteAccounts", "true},");
                perms.Add("UnlockAccounts", "true},");
                perms.Add("ManageSafe", "true},");
                perms.Add("ManageSafeMembers", "true},");
                perms.Add("BackupSafe", "true},");
                perms.Add("ViewAuditLog", "true},");
                perms.Add("ViewSafeMembers", "true},");
                perms.Add("AccessWithoutConfirmation", "true},");
                perms.Add("CreateFolders", "true},");
                perms.Add("DeleteFolders", "true},");
                perms.Add("MoveAccountsAndFolders", "true}");

                return perms;
            }
        }
        public static Dictionary<string, string> AllSafes
        {
            get
            {
                Dictionary<string, string> perms = new Dictionary<string, string>();

                perms.Add("UseAccounts", "false},");
                perms.Add("RetrieveAccounts", "false},");
                perms.Add("ListAccounts", "true},");
                perms.Add("AddAccounts", "false},");
                perms.Add("UpdateAccountContent", "false},");
                perms.Add("UpdateAccountProperties", "false},");
                perms.Add("InitiateCPMAccountManagementOperations", "false},");
                perms.Add("SpecifyNextAccountContent", "false},");
                perms.Add("RenameAccounts", "false},");
                perms.Add("DeleteAccounts", "false},");
                perms.Add("UnlockAccounts", "false},");
                perms.Add("ManageSafe", "false},");
                perms.Add("ManageSafeMembers", "false},");
                perms.Add("BackupSafe", "false},");
                perms.Add("ViewAuditLog", "false},");
                perms.Add("ViewSafeMembers", "false},");
                perms.Add("AccessWithoutConfirmation", "false},");
                perms.Add("CreateFolders", "false},");
                perms.Add("DeleteFolders", "false},");
                perms.Add("MoveAccountsAndFolders", "false}");

                return perms;
            }
        }
        public static Dictionary<string, string> VaultAdmins
        {
            get
            {
                Dictionary<string, string> perms = new Dictionary<string, string>();

                perms.Add("UseAccounts", "true},");
                perms.Add("RetrieveAccounts", "true},");
                perms.Add("ListAccounts", "true},");
                perms.Add("AddAccounts", "true},");
                perms.Add("UpdateAccountContent", "true},");
                perms.Add("UpdateAccountProperties", "true},");
                perms.Add("InitiateCPMAccountManagementOperations", "true},");
                perms.Add("SpecifyNextAccountContent", "true},");
                perms.Add("RenameAccounts", "true},");
                perms.Add("DeleteAccounts", "true},");
                perms.Add("UnlockAccounts", "true},");
                perms.Add("ManageSafe", "true},");
                perms.Add("ManageSafeMembers", "true},");
                perms.Add("BackupSafe", "true},");
                perms.Add("ViewAuditLog", "true},");
                perms.Add("ViewSafeMembers", "true},");
                perms.Add("AccessWithoutConfirmation", "true},");
                perms.Add("CreateFolders", "true},");
                perms.Add("DeleteFolders", "true},");
                perms.Add("MoveAccountsAndFolders", "true}");

                return perms;
            }
        }
        public static Dictionary<string, string> Administrators
        {
            get
            {
                Dictionary<string, string> perms = new Dictionary<string, string>();

                perms.Add("UseAccounts", "true},");
                perms.Add("RetrieveAccounts", "true},");
                perms.Add("ListAccounts", "true},");
                perms.Add("AddAccounts", "true},");
                perms.Add("UpdateAccountContent", "true},");
                perms.Add("UpdateAccountProperties", "true},");
                perms.Add("InitiateCPMAccountManagementOperations", "true},");
                perms.Add("SpecifyNextAccountContent", "true},");
                perms.Add("RenameAccounts", "true},");
                perms.Add("DeleteAccounts", "true},");
                perms.Add("UnlockAccounts", "true},");
                perms.Add("ManageSafe", "true},");
                perms.Add("ManageSafeMembers", "true},");
                perms.Add("BackupSafe", "true},");
                perms.Add("ViewAuditLog", "true},");
                perms.Add("ViewSafeMembers", "true},");
                perms.Add("AccessWithoutConfirmation", "true},");
                perms.Add("CreateFolders", "true},");
                perms.Add("DeleteFolders", "true},");
                perms.Add("MoveAccountsAndFolders", "true}");

                return perms;
            }
        }
        public static Dictionary<string, string> User
        {
            get
            {
                Dictionary<string, string> perms = new Dictionary<string, string>();

                perms.Add("UseAccounts", "true},");
                perms.Add("RetrieveAccounts", "true},");
                perms.Add("ListAccounts", "true},");
                perms.Add("AddAccounts", "false},");
                perms.Add("UpdateAccountContent", "false},");
                perms.Add("UpdateAccountProperties", "false},");
                perms.Add("InitiateCPMAccountManagementOperations", "true},");
                perms.Add("SpecifyNextAccountContent", "false},");
                perms.Add("RenameAccounts", "false},");
                perms.Add("DeleteAccounts", "false},");
                perms.Add("UnlockAccounts", "false},");
                perms.Add("ManageSafe", "false},");
                perms.Add("ManageSafeMembers", "false},");
                perms.Add("BackupSafe", "false},");
                perms.Add("ViewAuditLog", "false},");
                perms.Add("ViewSafeMembers", "false},");
                perms.Add("AccessWithoutConfirmation", "false},");
                perms.Add("CreateFolders", "false},");
                perms.Add("DeleteFolders", "false},");
                perms.Add("MoveAccountsAndFolders", "false}");

                return perms;
            }
        }
    }
}
