from rest_framework.response import Response 
from django.http import HttpResponseRedirect
from rest_framework.decorators import api_view
import requests
import time
import json
import base64
from bs4 import BeautifulSoup
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile'
]
CLIENT_SECRET_FILE = "env/credentials.json"
AUTH_REDIRECT_URI = "http://localhost:8000/auth"
CLIENT_ID = ""
CLIENT_SECRET = ""
userCredentialsSession = {}

def getClientSecret():
    f = open('env/credentials.json')
    client_creds = json.load(f)
    return (client_creds['web']['client_id'],client_creds['web']['client_secret'])

CLIENT_ID,CLIENT_SECRET = getClientSecret()



@api_view(['GET'])
def home(request):
    greet = "Hello User"
    return Response(greet)

@api_view(['GET'])
def getAuthURI(request):
    flow = Flow.from_client_secrets_file(CLIENT_SECRET_FILE,scopes=' '.join(SCOPES),redirect_uri = AUTH_REDIRECT_URI)
    uri,state = flow.authorization_url(prompt = 'consent',access_type='offline',include_granted_scopes='true')
    #url = "https://accounts.google.com/o/oauth2/v2/auth?scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fgmail.readonly&access_type=offline&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fauth&client_id=814936498158-s78afmmh7gcj8uglstaptgpc3ocreoeo.apps.googleusercontent.com"
    return Response(uri)

@api_view(['GET'])
def authorize(request):
    code = request.query_params['code']
    scope = request.query_params['scope']
    #timestamp = request.query_params['timestamp']
    # GOOGLE_URL = "https://oauth2.googleapis.com/token"
    # REDIRECT_URI = "http://localhost:8000/auth"
    # grant_type = "authorization_code"
    # response = requests.post(url=GOOGLE_URL,data={
    #     'redirect_uri' : AUTH_REDIRECT_URI,
    #     'client_id':CLIENT_ID,
    #     'client_secret': CLIENT_SECRET,
    #     'code': code,
    #     'grant_type' : grant_type,
    # })
    # result = response.json()
    # accessToken = result['access_token']
    # expiresIn = result['expires_in']
    # refreshToken = result['refresh_token']
    # tokenType = result['token_type']

    #fetch all mails from past 60 minutes
    timestamp = int(time.time()) - 3600
    flow = Flow.from_client_secrets_file(CLIENT_SECRET_FILE,scopes = ' '.join(SCOPES) + ' openid ',redirect_uri = AUTH_REDIRECT_URI)
    flow.fetch_token(code = code)
    cred = flow.credentials
    session = flow.authorized_session()
    userInfo = session.get('https://www.googleapis.com/userinfo/v2/me').json()
    emails = fetchEmails(cred,timestamp)
    userCredentialsSession[userInfo['email']] = [cred,session]    
    return Response("Name : "+userInfo['name']+" Email : "+ userInfo['email'] + " Emails: "+str(emails))

@api_view(['GET'])
def getEmails(request):
    timestamp = request.query_params['timestamp']
    if not timestamp:
        return Response("Invalid Request please provide a timestamp")
    timestamp = int(timestamp)
    email = request.query_params['email']
    if email not in userCredentialsSession.keys:
        return HttpResponseRedirect("/getoauthuri")
    else:
        emails = fetchEmails(userCredentialsSession[email][0],timestamp)
        return Response("emails : ",str(emails))

def fetchEmails(credentials,timestamp):
    service = build('gmail','v1',credentials=credentials)
    #result = service.users().messages().list(userId='me' ,q='after:1692925196' + 'before:1692925356').execute()
    result = service.users().messages().list(userId = 'me',q ='after:'+str(timestamp)).execute()
    count = result['resultSizeEstimate']
    if count==0:
        return {}
    messages = result['messages']
    emails = {}
    for message in messages:
        m = service.users().messages().get(userId='me',id=message['id']).execute()
        payload = m['payload']
        headers = payload['headers']

        for d in headers:
            if d['name'] == 'Subject':
                subject = d['value']
            if d['name'] == 'From':
                sender = d['value']

        #Decoding the base64 email body
        parts = payload.get('parts')[0]
        data = parts['body']['data']
        data = data.replace("-","+").replace("_","/")
        decoded_data = base64.b64decode(data)

        #decoding the lxml data generated from base64.b64decode
        soup = BeautifulSoup(decoded_data , "lxml")
        body = soup.body()

        emails[message['id']] = {
            'subject':subject,
            'from':sender,
            'message':body,
        }
    return emails