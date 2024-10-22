import os
import json
import requests
import boto3
from warrant.aws_srp import AWSSRP
from botocore.session import Session
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from dotenv import load_dotenv
import time

load_dotenv()


class AWSAppSyncClient:
    def __init__(self, username, password, useRefreshToken=False):
        self.username = username
        self.password = password
        self.useRefreshToken = useRefreshToken
        self.endpoint = os.getenv("AWS_APPSYNC_GRAPHQL_ENDPOINT")
        self.region = os.getenv("AWS_APPSYNC_REGION")
        self.user_pools_id = os.getenv("AWS_USER_POOLS_ID")
        self.user_pools_web_client_id = os.getenv("AWS_USER_POOLS_WEB_CLIENT_ID")
        self.cognito_region = os.getenv("AWS_COGNITO_REGION")
        self.identity_pool_id = os.getenv("AWS_COGNITO_IDENTITY_POOL_ID")
        self.refresh_token_path = ".refresh_token"
        self._authenticate()
        self._setup_identity()
        self._get_auth_email()

    def _authenticate(self):
        if self.useRefreshToken and os.path.exists(self.refresh_token_path):
            with open(self.refresh_token_path, "r") as file:
                refresh_token = file.read()
            try:
                self._refresh_authentication(refresh_token)
                print(f"Connected using refresh token")
            except Exception as e:
                print(
                    "Refresh token expired or invalid, falling back to username/password authentication."
                )
                self._new_user_authentication()
                print(f"Connected using username and password")
        elif self.username and self.password:
            self._new_user_authentication()
            print(f"Connected using username and password")
        else:
            raise Exception("Cannot authenticate: No valid credentials provided.")

    def _new_user_authentication(self):
        aws_srp = AWSSRP(
            username=self.username,
            password=self.password,
            pool_id=self.user_pools_id,
            client_id=self.user_pools_web_client_id,
            pool_region=self.cognito_region,
        )
        cognito_client = boto3.client("cognito-idp", region_name=self.cognito_region)
        self.tokens = aws_srp.authenticate_user()

        if self.tokens.get("ChallengeName") == "SOFTWARE_TOKEN_MFA":
            mfa_code = input(f"Enter MFA code for account {self.username}: ")
            response = cognito_client.respond_to_auth_challenge(
                ClientId=self.user_pools_web_client_id,
                ChallengeName="SOFTWARE_TOKEN_MFA",
                Session=self.tokens["Session"],
                ChallengeResponses={
                    "USERNAME": self.username,
                    "SOFTWARE_TOKEN_MFA_CODE": mfa_code,
                },
            )
            self.tokens = response.get("AuthenticationResult")
        else:
            self.tokens = self.tokens.get("AuthenticationResult")
        self._store_refresh_token()  # Store refresh token every successful authentication

    def _refresh_authentication(self, refresh_token):
        client = boto3.client("cognito-idp", region_name=self.cognito_region)
        response = client.initiate_auth(
            ClientId=self.user_pools_web_client_id,
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters={
                "REFRESH_TOKEN": refresh_token,
            },
        )
        if "AuthenticationResult" in response:
            self.tokens = response["AuthenticationResult"]
            self._store_refresh_token()  # Store new refresh token
        else:
            raise Exception(
                "Failed to refresh authentication with the provided refresh token."
            )

    def _store_refresh_token(self):
        if "RefreshToken" in self.tokens:
            with open(self.refresh_token_path, "w") as file:
                file.write(self.tokens["RefreshToken"])

    def _setup_identity(self):
        identity_client = boto3.client(
            "cognito-identity", region_name=self.cognito_region
        )
        id_response = identity_client.get_id(
            IdentityPoolId=self.identity_pool_id,
            Logins={
                f"cognito-idp.{self.cognito_region}.amazonaws.com/{self.user_pools_id}": self.tokens[
                    "IdToken"
                ]
            },
        )
        self.identity_id = id_response["IdentityId"]
        credentials_response = identity_client.get_credentials_for_identity(
            IdentityId=self.identity_id,
            Logins={
                f"cognito-idp.{self.cognito_region}.amazonaws.com/{self.user_pools_id}": self.tokens[
                    "IdToken"
                ]
            },
        )
        self.credentials = credentials_response["Credentials"]

    def execute_query(self, query, variables=None):
        session = Session()
        session.set_credentials(
            self.credentials["AccessKeyId"],
            self.credentials["SecretKey"],
            self.credentials["SessionToken"],
        )
        auth = SigV4Auth(session.get_credentials(), "appsync", self.region)
        headers = {"Content-Type": "application/json"}
        request = AWSRequest(
            method="POST",
            url=self.endpoint,
            data=json.dumps({"query": query, "variables": variables}),
            headers=headers,
        )
        auth.add_auth(request)
        response = requests.post(
            request.url, data=request.data, headers=dict(request.headers)
        )
        try:
            return json.loads(response.text)
        except KeyError:
            return response.text

    def _get_auth_email(self):
        query = """
        query getUser {
          userGetUser {
            email
            firstName
            lastName
          }
        }
        """

        result = self.execute_query(query)
        try:
            user_email = result["data"]["userGetUser"]["email"]
            print(f"Connected as {user_email}")
            return user_email
        except KeyError:
            print("Could not retrieve user email from the response.")
            exit(1)

    def get_devices(self):
        query = """
        query queryUserDevices {
          userListUserDevices {
            device {
              online
            }
            deviceId
            deviceLabel
          }
        }
        """

        response = self.execute_query(query)

        res = []

        try:
            for device in response["data"]["userListUserDevices"]:
                res.append(
                    {
                        "deviceId": device["deviceId"],
                        "deviceLabel": device["deviceLabel"],
                        "online": device["device"]["online"],
                    }
                )
            return res
        except KeyError:
            print("Could not retrieve devices from the response.")
            return []

    def get_sensors_data(self, input):
        query = """
        query getIoData($input: IoDataInput!) {
          userGetIoData(input: $input) {
            logging {
              list
              timestamp
            }
            nextToken
          }
        }
        """

        response = self.execute_query(query, {"input": input})

        res = {}

        try:
            res["nextToken"] = response["data"]["userGetIoData"]["nextToken"]
            for log in response["data"]["userGetIoData"]["logging"]:
                res[log["timestamp"]] = {}
                res[log["timestamp"]]["S1TopStorageTank"] = log["list"][0]
                res[log["timestamp"]]["S2HotWater"] = log["list"][1]
                res[log["timestamp"]]["S3StorageTankReference"] = log["list"][2]
                res[log["timestamp"]]["S4TopHeatingBuffer"] = log["list"][3]
                res[log["timestamp"]]["S10OutdoorTemperature"] = log["list"][9]
                res[log["timestamp"]]["S11Circulation"] = log["list"][10]
                res[log["timestamp"]]["S12HeatingCircuit1Flow"] = log["list"][11]
                res[log["timestamp"]]["S15ColdWater"] = log["list"][14]
                res[log["timestamp"]]["S18HotWaterVolumeFlow"] = log["list"][17]
            return res
        except KeyError:
            print("Could not retrieve sensor data from the response.")
            return {}

    def get_current_sensors_data(self, device_id):
        end = int(time.time())
        start = end - 86400

        res = self.get_sensors_data(
            {
                "deviceId": device_id,
                "limit": 1000,
                "start": start,
                "end": end,
            }
        )

        return res[list(res.keys())[-1]]

    def set_heating_mode(self, device_id, mode):
        query = """
        mutation setParameters($input: setParametersInput!) {
          userSetParameters(input: $input) {
            changeId
          }
        }
        """

        param = None

        if mode == "AUTO":
            param = [11, 2, 2]
        elif mode == "DAY":
            param = [11, 2, 3]
        elif mode == "LOWERING":
            param = [11, 2, 4]
        elif mode == "STANDBY":
            param = [11, 2, 5]
        elif mode == "ECO":
            param = [11, 2, 6]
        else:
            print("Invalid mode")
            return

        response = self.execute_query(
            query,
            {"input": {"deviceId": device_id, "newParameters": [param]}},
        )

        try:
            return response["data"]["userSetParameters"]["changeId"]
        except KeyError:
            print("Could not retrieve changeId from the response.")
            return None
