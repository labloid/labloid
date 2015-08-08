from flask.ext.wtf import Form
from wtforms import StringField, TextAreaField, BooleanField, SelectField, \
    SubmitField
from wtforms.validators import required, Length, Email, Regexp
from wtforms import ValidationError
from flask.ext.pagedown.fields import PageDownField
from wtforms.widgets import TextArea
from ..models import GroupRole, User, PostGroup, GroupMemberShip

class EditMemberShipRoleForm(Form):
    role = SelectField('Role', coerce=int)
    submit = SubmitField('Submit')
    cancel = SubmitField('Cancel')

    def __init__(self, user_id, group_id, *args, **kwargs):
        super(EditMemberShipRoleForm, self).__init__(*args, **kwargs)
        self.user = User.query.filter_by(id=user_id).first_or_404()
        self.group = PostGroup.query.filter_by(id=group_id).first_or_404()

        self.role.choices = [(role.id, role.name)
                             for role in GroupRole.query.order_by(GroupRole.name).all()]
        self.membership = GroupMemberShip.query.filter_by(member_id=user_id, group_id=group_id).first_or_404()
        self.choice_map = dict(self.role.choices)



class GroupForm(Form):
    groupname = StringField('Group Name', validators=[required(), Length(1, 64)])
    description = StringField('Description')
    invites = StringField('Invite Members', widget=TextArea(),
                          default='comma separated email adresses or user names')
    submit = SubmitField('Submit')

    def __init__(self, user, *args, **kwargs):
        super(GroupForm, self).__init__(*args, **kwargs)
        self.user = user

    def validate_groupname(self, field):
        if self.user.is_in_group_named(field.data):
            raise ValidationError('User already has group named %s' % (field.data,))


class AddMembersForm(Form):
    invites = StringField('Invite Members', widget=TextArea(), default='comma separated email adresses or user names')
    submit = SubmitField('Invite')

    def __init__(self, group_id, *args, **kwargs):
        super(AddMembersForm, self).__init__(*args, **kwargs)
        self.group = PostGroup().query.filter_by(id=group_id).first_or_404()

    def validate_invites(self, field):
        for invitee in map(lambda x: x.strip(), field.data.split(',')):
            if not '@' in invitee and User().query.filter_by(username=invitee).count() == 0:
                raise ValidationError('User does not exist')

class ConfirmationForm(Form):
    sure = SubmitField('Yes, I am sure!')
    cancel = SubmitField('No, take me back!')
