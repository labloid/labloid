from flask.ext.wtf import Form
from wtforms import StringField, TextAreaField, BooleanField, SelectField, \
    SubmitField
from wtforms.validators import required, Length, Email, Regexp
from wtforms import ValidationError
from flask.ext.pagedown.fields import PageDownField
from wtforms.widgets import TextArea
from ..models import GroupRole, User, PostGroup


class EditProfileForm(Form):
    name = StringField('Real name', validators=[Length(0, 64)])
    submit = SubmitField('Submit')


class EditProfileAdminForm(Form):
    email = StringField('Email', validators=[required(), Length(1, 64),
                                             Email()])
    username = StringField('Username', validators=[
        required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                          'Usernames must have only letters, '
                                          'numbers, dots or underscores')])
    confirmed = BooleanField('Confirmed')
    role = SelectField('GroupRole', coerce=int)
    name = StringField('Real name', validators=[Length(0, 64)])
    submit = SubmitField('Submit')

    def __init__(self, user, *args, **kwargs):
        super(EditProfileAdminForm, self).__init__(*args, **kwargs)
        self.role.choices = [(role.id, role.name)
                             for role in GroupRole.query.order_by(GroupRole.name).all()]
        self.user = user

    def validate_email(self, field):
        if field.data != self.user.email and \
                User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if field.data != self.user.username and \
                User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')


class EditMemberShipForm(Form):
    role = SelectField('Role', coerce=int)
    submit = SubmitField('Submit')
    delete = SubmitField('Delete')
    cancel = SubmitField('Cancel')

    def __init__(self, user_id, group_id, *args, **kwargs):
        super(EditMemberShipForm, self).__init__(*args, **kwargs)
        self.role.choices = [(role.id, role.name)
                             for role in GroupRole.query.order_by(GroupRole.name).all()]
        self.choice_map = dict(self.role.choices)
        self.user = User().query.filter_by(id=user_id).first_or_404()
        self.group = PostGroup().query.filter_by(id=group_id).first_or_404()


class PostForm(Form):
    body = PageDownField("What's on your mind?", validators=[required()])
    submit = SubmitField('Submit')


class CommentForm(Form):
    body = StringField('Enter your comment', validators=[required()])
    submit = SubmitField('Submit')


class GroupForm(Form):
    groupname = StringField('Group Name', validators=[required(), Length(1, 64)])
    description = StringField('Description')
    invites = StringField('Invite Members', widget=TextArea(),
                          default='comma separated email adresses or user names')
    submit = SubmitField('Submit')


class AddMembersForm(Form):
    invites = StringField('Invite Members', widget=TextArea(), default='comma separated email adresses or user names')
    submit = SubmitField('Invite')

    def __init__(self, group_id, *args, **kwargs):
        super(AddMembersForm, self).__init__(*args, **kwargs)
        self.group = PostGroup().query.filter_by(id=group_id).first_or_404()

    def validate_invitees(self, field):
        for invitee in map(lambda x: x.strip(), field.data.split(',')):
            if not '@' in invitee and User().query.filter_by(username=invitee).count() == 0:
                raise ValidationError('User does not exist')
