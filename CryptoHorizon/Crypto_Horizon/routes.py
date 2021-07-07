from flask import render_template, url_for, flash, redirect, request
from Crypto_Horizon.horizonforms import RegistrationForm, LoginForm, TransferForm, UpdateAccountForm, RequestResetForm, ResetPasswordForm, TopUpForm
from urllib.request import urlopen
from Crypto_Horizon import db, app, bcrypt, mail
from Crypto_Horizon.models import User, Transaction
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Message
from pycoingecko import CoinGeckoAPI
from web3 import Web3

# Provide http provider, pass in mainet url
ganache_url = 'http://127.0.0.1:7545'
web3 = Web3(Web3.HTTPProvider(ganache_url))

cg = CoinGeckoAPI()





posts = [
    {
        'author': 'Crypto_Horizon Pay',
        'title': 'Borderless Transfer',
        'content': 'Send Ghanaian Cedis to any African country, Fast and Fee - Less',
        'date_posted': 'March 21, 2020'
    },
    {
        'author': 'Crypto_Horizon Pay',
        'title': 'African Currency Exchange',
        'content': 'Check and Change Your Cedis Into Any African Currency',
        'date_posted': 'April 21, 2018'
    }
]

@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html', posts=posts)


@app.route("/about")
def about():
    return render_template('about.html', title='About', posts=posts)

@app.route("/exchangerates", methods=['GET', 'POST'])
def exchangerates():
    keys = []
    unsorted_values = []
    prepped_values = []
    vals = []
    data = {}

    x =cg.get_price(ids=['bitcoin','ethereum', 'cardano', 'litecoin','ripple', 'binance','chainlink','polkadot','yfi','usd'], vs_currencies='ngn')
    dictkeys =  x.keys()
    dictvalues = x.values()

    for i in dictkeys:
        keys.append(i)
    for j in dictvalues:
        j = j.values()
        unsorted_values.append(j)
    for l in unsorted_values:
        for u in l:
            vals.append(u)

    for key, val in zip(keys, vals):
        data[key] = data.get(key, 0) + val
    #currency_conversion('GHS_DZD')
    #output = currency_conversion('GHS_DZD').exchange

    output = data['bitcoin']
    output_1 = data['ethereum']
    output_2 = data['cardano']
    output_3 = data['ripple']
    output_4 = data['chainlink']
    output_5 = data['polkadot']
    output_6 = data['litecoin']
    return render_template('exchangerates.html', title='Exchange Rates', output=output, output_1=output_1, output_2=output_2, output_3=output_3, output_4 =output_4, output_5=output_5, output_6=output_6 )


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password, account_address=form.address.data)
        db.session.add(user)
        db.session.commit()
        flash(f'Account created for {form.username.data}! You may log in now', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route("/transfermoney", methods=['GET', 'POST'])
@login_required
def transfermoney():
    form = TransferForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=current_user.username).first()
        user_2 = User.query.filter_by(username=form.receiving_username.data).first()
        if bcrypt.check_password_hash(user.password, form.password.data):
            transactions = Transaction(from_user_id=current_user.id, receiving_user_id=user_2.id, amount=form.amount.data)
            IsConnected = web3.isConnected()
            print(IsConnected)
            balance = web3.eth.getBalance(current_user.account_address)
            ether_bal = web3.fromWei(balance, 'ether')
            if ether_bal < transactions.amount:
                flash('Insufficient Funds')
            else:
                # addresses of test accounts
                account_1 = current_user.account_address
                account_2 = user_2.account_address

                private_key = form.private_keys.data

                # get nonce(stops from sending transaction twice).
                nonce = web3.eth.getTransactionCount(account_1)

                # build transaction via form a dict
                tx = {
                    'nonce': nonce,
                    'to': account_2,
                    'value': web3.toWei(form.amount.data, 'ether'),
                    'gas': 3000000,
                    'gasPrice': web3.eth.gas_price,
                }

                signed_tx = web3.eth.account.signTransaction(tx, private_key)
                tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
                g = web3.eth.gas_price
                h= (web3.toHex(tx_hash))
            flash(f'Transfer Successful. {g} gas fees and tx hash {h}')
            return redirect(url_for('transfermoney'))
        else:
            flash('Transfer Unsuccessful. Please check password', 'danger')
    return render_template('transfermoney.html', title='Transfer Money', form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    return render_template('account.html', title='Account', form=form)

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='noreply@demo.com',
                  recipients=[user.email])
    msg.body = f''' To reset your password, visit the following link:
    {url_for('reset_token', token=token, _external=True)}
    
    If you did not make request then simply ignore this email and no changes will be made
    '''


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template ('reset_request.html', title='Reset Password', form=form)

@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('The password has been updated! You may log in now', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form= form)

@app.route("/wallet")
@login_required
def wallet():
    # checking app is connect to blockchain
    IsConnected = web3.isConnected()
    blocknum = web3.eth.blockNumber
    print(IsConnected)
    balance = web3.eth.getBalance(current_user.account_address)
    ether_bal = web3.fromWei(balance, 'ether')


    return render_template('wallet.html', title='Wallet', bal = ether_bal)

@app.route("/topup", methods=['GET', 'POST'])
@login_required
def topup():
    form = TopUpForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=current_user.username).first()
        if bcrypt.check_password_hash(user.password, form.password.data):
             addition = int(form.amount.data)
             current_user.account_balance += addition
             db.session.commit()
             flash('Top Up Successful', 'success')
             return redirect(url_for('wallet'))
        else:
            flash('Top Up Unsuccessful. Please check password', 'danger')
    return render_template('topup.html', title='Top Up Wallet', form=form)

