from Crypto_Horizon import db, login_manager, app
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_login import UserMixin
from datetime import datetime


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    account_address = db.Column(db.String(60), nullable=False)
    transactions = db.relationship('Transaction', primaryjoin="and_(User.id==Transaction.from_user_id, User.id==Transaction.receiving_user_id)", lazy=True)


    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)



    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.account_balance})"

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    from_username = db.relationship('User', backref=db.backref('sent_transactions', uselist=False, lazy='joined'),
        foreign_keys=[from_user_id])

    receiving_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiving_username = db.relationship('User', backref=db.backref('received_transactions', uselist=False, lazy='joined'), foreign_keys=[receiving_user_id])
    amount = db.Column(db.Integer, nullable=False)
    currency = db.Column(db.String, nullable=False)
    date_sent = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
       return f"Transaction('{self.from_username}', '{self.amount}','{self.currency}', '{self.receiving_username}', '{self.date_sent})"


