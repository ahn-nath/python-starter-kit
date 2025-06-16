from datetime import date
from functools import wraps

from flask import Flask, url_for, render_template, request, session, jsonify, redirect
from kinde_sdk import Configuration, ApiException
from kinde_sdk.apis.tags import users_api
from kinde_sdk.kinde_api_client import GrantType, KindeApiClient

from flask_session import Session

app = Flask(__name__)
app.config.from_object("config")
Session(app)

configuration = Configuration(host=app.config["KINDE_ISSUER_URL"])
kinde_api_client_params = {
    "configuration": configuration,
    "domain": app.config["KINDE_ISSUER_URL"],
    "client_id": app.config["CLIENT_ID"],
    "client_secret": app.config["CLIENT_SECRET"],
    "grant_type": app.config["GRANT_TYPE"],
    "callback_url": app.config["KINDE_CALLBACK_URL"],
}
if app.config["GRANT_TYPE"] == GrantType.AUTHORIZATION_CODE_WITH_PKCE:
    kinde_api_client_params["code_verifier"] = app.config["CODE_VERIFIER"]

kinde_client = KindeApiClient(**kinde_api_client_params)
user_clients = {}


def get_authorized_data(kinde_client):
    user = kinde_client.get_user_details()
    return {
        "id": user.get("id"),
        "user_given_name": user.get("given_name"),
        "user_family_name": user.get("family_name"),
        "user_email": user.get("email"),
        "user_picture": user.get("picture"),
    }


def login_required(user):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not user.is_authenticated():
                return app.redirect(url_for('index'))
            return f(*args, **kwargs)

        return decorated_function

    return decorator


'''
@app.route("/")
def index():
    # data = {"current_year": date.today().year}
    data = {
        "current_year": date.today().year,
        "register_url": kinde_client.get_register_url({ 
            "auth_url_params": {
                "org_code": "your_dynamic_org_code"  
            }
        }),
        "login_url": kinde_client.get_login_url({
            "auth_url_params": {
                "org_code": "org_800ae4346c69"
            }
        })
    }
    template = "logged_out.html"

    if session.get("user"):
        kinde_client_ = user_clients.get(session.get("user"))

        if kinde_client_ and kinde_client_.is_authenticated():
            data.update(get_authorized_data(kinde_client_))
            template = "home.html"

    return render_template(template, **data)
'''

'''
@app.route("/")
def index():
    """
        The main route of the application. This will receive an email as an input to determine the organization and then
        pass it as an argument to the Kinde login URL. The user will be redirected to the Kinde login page
        with the organization code

        :return: render_template with the current year
    """
    data = {"current_year": date.today().year}
    template = "logged_out.html"

    if session.get("user"):
        kinde_client_ = user_clients.get(session.get("user"))

        if kinde_client_ and kinde_client_.is_authenticated():
            data.update(get_authorized_data(kinde_client_))
            template = "home.html"

    return render_template(template, **data)
'''


def get_user_organization_code(email):
    # Get user details
    user_details = kinde_client.get_user_details()

    # Check if the email matches
    if user_details.get("email") == email:
        # Get organization details
        org_details = kinde_client.get_organization()
        return org_details.get("code") if org_details else None

    return None


def get_organization_from_email(email):
    """
       To fully implement this option you need to create a database that keeps records of registered users and
       the relevant organization

       :param email:
       :return: organization code
    """

    if not email:
        return None

    # Extract the domain from the email
    email_domain = email.split('@')[-1]

    """
        IMPORTANT NOTE: This logic is meant to be used as an example of how the core logic of matching email domain with 
        org would work quickly. It should and could be replaced with a database lookup or a more robust solution.
        The database lookup could be based on the user record or on the organization record (e.g. the org code has a 
        record and the domain is stored there as a column of the row or the user record has a column with the org code 
        and the email)
        
        So this could look like:
        
        user lookup: ORM call to get user by email, and the object has the org code --> user.organization.org_code OR
        user.org_code
        org lookup: ORM call to get org by domain, and the object has the org code --> org.org_code
        
        The example below is based on organization lookup. Please adjust as needed, the point is having a logic that
        allows you to get the org code from the email domain or email, in the case of user lookup.  
    """
    organization_mapping = {
        "org1.com": "org_800ae4346c69",
        "org2.com": "org_dddca967a530"
    }

    # Check if the domain matches any organization
    for domain, org_code in organization_mapping.items():
        if email_domain == domain:
            return org_code

    return None


@app.route("/", methods=['GET', 'POST'])
def index():
    """
        Main route handling email submission and organization detection.
        Processes form input to determine organization code and redirects accordingly.
    """
    template = "logged_out_central.html"
    data = {"current_year": date.today().year}

    if request.method == 'POST':
        email = request.form.get('email')
        # organization validation logic here
        organization_code = get_organization_from_email(email)

        if organization_code:
            # Redirect to Kinde login with organization code
            login_url = kinde_client.get_login_url({
                "auth_url_params": {
                    # "org_code": organization_code,
                    # "connection_id": "conn_019506549e97ba3c4a40ec916aefe8bd",
                    # "login_hint": "phone:"
                    "prompt": "none",
                    "redirect_uri": "http://app2.localtest.me:5000/auth/callback", # NOTE: Check with Kinde if we can
                    # pass this parameter # TODO: Update this as a callback in Kinde (?)
                }
            })
            return redirect(login_url)
        else:
            data['error'] = "Invalid email domain or organization not found"

    if session.get("user"):
        kinde_client_ = user_clients.get(session.get("user"))
        if kinde_client_ and kinde_client_.is_authenticated():
            data.update(get_authorized_data(kinde_client_))
            template = "home.html"

    return render_template(template, **data)


'''
@app.route("/", methods=['GET', 'POST'])
def index():
    """
    Main route handling organization selection via buttons.
    Processes button input to determine organization code and redirects accordingly.
    """
    template = "logged_out_central.html"
    data = {"current_year": date.today().year}
    allowed_organizations = {
        "org_800ae4346c69": "Test Organization 1",
        "org_dddca967a530": "Test Organization 2"
    }

    if request.method == 'POST':
        organization_code = request.form.get('organization')

        if organization_code in allowed_organizations:
            login_url = kinde_client.get_login_url({
                "auth_url_params": {
                    "org_code": organization_code,
                    "login_hint": "hello@gmail.com"
                }
            })
            kinde_client.get_login_url()
            return redirect(login_url)
        else:
            data['error'] = "Invalid organization selection"

    if session.get("user"):
        kinde_client_ = user_clients.get(session.get("user"))
        if kinde_client_ and kinde_client_.is_authenticated():
            data.update(get_authorized_data(kinde_client_))
            template = "home.html"

    data['organizations'] = allowed_organizations
    return render_template(template, **data)
'''


@app.route("/api/auth/login")
def login():
    return app.redirect(kinde_client.get_login_url())


@app.route("/api/auth/register")
def register():
    return app.redirect(kinde_client.get_register_url())


@app.route("/add_organization")
def add_organization():
    return app.redirect(kinde_client.create_org())


@app.route("/api/auth/kinde_callback")
def callback():
    kinde_client.fetch_token(authorization_response=request.url)
    data = {"current_year": date.today().year}
    data.update(get_authorized_data(kinde_client))
    session["user"] = data.get("id")
    user_clients[data.get("id")] = kinde_client

    # Get user organizations here
    orgs = kinde_client.get_user_organizations()
    print("User Organizations:", orgs)

    return app.redirect(url_for("index"))


@app.route("/api/auth/logout")
def logout():
    user_clients[session.get("user")] = None
    session["user"] = None
    return app.redirect(
        kinde_client.logout(redirect_to=app.config["LOGOUT_REDIRECT_URL"])
    )


@app.route("/details")
def get_details():
    template = "logged_out.html"
    data = {"current_year": date.today().year}

    if session.get("user"):
        kinde_client = user_clients.get(session.get("user"))

        if kinde_client:
            data = {"current_year": date.today().year}
            data.update(get_authorized_data(kinde_client))
            data["access_token"] = kinde_client.configuration.access_token
            data["organizations"] = kinde_client.get_user_organizations()
            # Print the ID and access token
            user_details = kinde_client.get_user_details()
            access_token = kinde_client.configuration.access_token
            print(f"User ID: {user_details.get('id')}")
            print(f"Access Token: {access_token}")
            print(f"Whatever: {kinde_client.client.token}")

            print(kinde_client.get_claim("groups"))

            print(kinde_client.get_claim("groups", "id_token"))  # ext_provider > claims* > profile > groups
            print(kinde_client.get_claim("organizations", "id_token"))  # ext_provider > claims* > access_token > groups

            template = "details.html"

    return render_template(template, **data)


@app.route("/helpers")
def get_helper_functions():
    template = "logged_out.html"

    if session.get("user"):
        kinde_client = user_clients.get(session.get("user"))
        data = {"current_year": date.today().year}

        if kinde_client:
            data.update(get_authorized_data(kinde_client))
            # print(kinde_client.configuration.access_token)
            data["claim"] = kinde_client.get_claim("iss")
            data["organization"] = kinde_client.get_organization()
            data["user_organizations"] = kinde_client.get_user_organizations()
            data["flag"] = kinde_client.get_flag("theme", "red")
            data["bool_flag"] = kinde_client.get_boolean_flag("is_dark_mode", False)
            data["str_flag"] = kinde_client.get_string_flag("theme", "red")
            data["int_flag"] = kinde_client.get_integer_flag("competitions_limit", 10)
            template = "helpers.html"



        else:
            template = "logged_out.html"

    return render_template(template, **data)


@app.route("/api_demo")
def get_api_demo():
    template = "api_demo.html"

    if session.get("user"):
        kinde_client = user_clients.get(session.get("user"))
        data = {"current_year": date.today().year}

        if kinde_client:
            data.update(get_authorized_data(kinde_client))

            try:
                kinde_mgmt_api_client = KindeApiClient(
                    configuration=configuration,
                    domain=app.config["KINDE_ISSUER_URL"],
                    client_id=app.config["MGMT_API_CLIENT_ID"],
                    client_secret=app.config["MGMT_API_CLIENT_SECRET"],
                    audience=f"{app.config['KINDE_ISSUER_URL']}/api",
                    callback_url=app.config["KINDE_CALLBACK_URL"],
                    grant_type=GrantType.CLIENT_CREDENTIALS,
                )

                api_instance = users_api.UsersApi(kinde_mgmt_api_client)
                api_response = api_instance.get_users()
                data['users'] = [
                    {
                        'first_name': user.get('first_name', ''),
                        'last_name': user.get('last_name', ''),
                        'total_sign_ins': int(user.get('total_sign_ins', 0))
                    }
                    for user in api_response.body['users']
                ]
                data['is_api_call'] = True

            except ApiException as e:
                data['is_api_call'] = False
                print("Exception when calling UsersApi %s\n" % e)
            except Exception as ex:
                data['is_api_call'] = False
                print(f"Management API not setup: {ex}")

    return render_template(template, **data)


# Organizations route
@app.route("/organizations")
def get_organizations():
    template = "logged_out.html"
    data = {"current_year": date.today().year}

    if session.get("user"):
        kinde_client = user_clients.get(session.get("user"))

        if kinde_client:
            data = {"current_year": date.today().year}
            data.update(get_authorized_data(kinde_client))
            data["organizations"] = kinde_client.get_user_organizations()["org_codes"]
            template = "organizations.html"

    return render_template(template, **data)


@app.route("/api/organizations")
def get_api_organizations():
    data = {"current_year": date.today().year}

    if session.get("user"):
        kinde_client = user_clients.get(session.get("user"))

        if kinde_client:
            data = {"current_year": date.today().year}
            data.update(get_authorized_data(kinde_client))
            data["organizations"] = kinde_client.get_user_organizations()["org_codes"]

    return jsonify(data)
