from flask import render_template, redirect, url_for, abort, flash, request, \
    current_app, make_response
from flask.ext.login import login_required, current_user
from flask.ext.sqlalchemy import get_debug_queries
from . import groups
from .forms import GroupForm, EditMemberShipRoleForm, AddMembersForm, ConfirmationForm
from .. import db
from ..models import Permission, GroupRole, User, Post, Comment, PostGroup, GroupMemberShip, GroupInvite
from .errors import forbidden
from .decorators import group_permission_required
from ..email import send_email

@groups.route('/edit-membership/<int:group_id>/<int:user_id>', methods=['GET', 'POST'])
@login_required
@group_permission_required(Permission.ADMINISTER, groupvar='group_id')
def edit_membership_role(user_id, group_id):
    # invite more members only if I can administer

    ms = GroupMemberShip.query.filter_by(member_id=user_id, group_id=group_id).first_or_404()

    form = EditMemberShipRoleForm(user_id=user_id, group_id=group_id)

    if form.validate_on_submit():
        if form.cancel.data:
            return redirect(url_for('.group', id=group_id))
        elif form.submit.data:
            if ms.member_can(Permission.ADMINISTER) \
                    and GroupRole.query.filter_by(id=form.role.data).first().name != 'Owner' \
                    and form.group.count_administrators() < 2:
                flash("A group needs at least one owner.")
            else:
                ms.role = GroupRole.query.get(form.role.data)
                db.session.add(ms)
                flash("%s's role has been updated to %s" % (ms.user.username, form.choice_map[form.role.data]))
                return redirect(url_for('.group', id=group_id))
    else:
        form.role.data = ms.grouprole_id

    return render_template('edit_membership.html', form=form)

@groups.route('/delete-membership/<int:group_id>/<int:user_id>', methods=['GET', 'POST'])
@login_required
@group_permission_required(Permission.ADMINISTER, groupvar='group_id')
def delete_membership(group_id, user_id):
    group = PostGroup.query.filter_by(id=group_id).first_or_404()
    user = User.query.filter_by(id=user_id).first_or_404()
    gm =  GroupMemberShip.query.filter_by(group_id=group_id, member_id=user_id).first_or_404()

    # we don't want to delete the last administrator
    if gm.member_can(Permission.ADMINISTER) and group.count_administrators() < 2:
        flash("You don't want to delete the last administrator.")
        return redirect(url_for('.group', id=group_id))


    form = ConfirmationForm()
    if form.validate_on_submit():
        if form.sure.data:
            gm =  GroupMemberShip.query.filter_by(group_id=group_id, member_id=user_id).first_or_404()
            db.session.delete(gm)
            flash('%s has been deleted from %s' % (gm.user.username, gm.group.groupname))
            return redirect(url_for('main.user', username=current_user.username))
        else:
            return redirect(url_for('.group', id=group_id))

    return render_template('groups/delete_membership.html', form=form)

@groups.route('/leave-group/<int:group_id>', methods=['GET', 'POST'])
@login_required
def leave_group(group_id):
    group = PostGroup.query.filter_by(id=group_id).first_or_404()

    if not current_user in group.users:
        flash("You can't leave a group you are not a member of.")
        return redirect(url_for('main.user', username=current_user.username))

    gm = group.memberships.filter_by(member_id=current_user.id).first_or_404()

    # we don't want to delete the last administrator
    if gm.member_can(Permission.ADMINISTER) and group.count_administrators() < 2:
        flash("You can't leave. You are the last administrator.")
        return redirect(url_for('.group', id=group_id))

    form = ConfirmationForm()
    if form.validate_on_submit():
        if form.sure.data:
            db.session.delete(gm)
            flash('You have left from %s' % (gm.group.groupname, ))
            return redirect(url_for('main.user', username=current_user.username))
        else:
            return redirect(url_for('.group', id=group_id))

    return render_template('groups/leave_group.html', form=form)



@groups.route('/group/<int:id>',  methods=['GET', 'POST'])
@login_required
def group(id):
    group = PostGroup.query.filter_by(id=id).first_or_404()
    if not current_user.is_member_of(group):
        return forbidden('You do not have the rights to see this group!')

    return render_template('groups/group.html', group=group, me=current_user)


@groups.route('/edit-group/<int:group_id>', methods=['GET', 'POST'])
@login_required
@group_permission_required(Permission.ADMINISTER, groupvar='group_id')
def edit_group(group_id):
    form = GroupForm()
    pg = PostGroup.query.filter_by(id=group_id).first_or_404()
    if form.validate_on_submit():
        pg.description = form.description.data
        pg.groupname = form.groupname.data

        db.session.add(pg)
        db.session.commit()

        flash('Group %s has been updated' % (form.groupname.data,))
        return redirect(url_for('.group', id=pg.id))
    else:
        form.description.data = pg.description
        form.groupname.data = pg.groupname

    return render_template('groups/edit_group.html', form=form, title='Edit Group')

@groups.route('/create-group', methods=['GET', 'POST'])
@login_required
def create_group():
    form = GroupForm()
    if form.validate_on_submit():

        pg = PostGroup(groupname=form.groupname.data,
                       description=form.description.data)
        gm = GroupMemberShip()
        gm.group = pg
        gm.role = GroupRole.query.filter_by(name='Owner').first_or_404()
        current_user.groupmemberships.append(gm)

        db.session.add(pg)
        db.session.add(gm)
        db.session.commit()

        flash('Group %s has been created' % (form.groupname.data,))
        return redirect(url_for('.group', id=pg.id))
    return render_template('groups/edit_group.html', form=form, title='Create Group')

@groups.route('/delete-group/<int:group_id>', methods=['GET', 'POST'])
@login_required
@group_permission_required(Permission.ADMINISTER, groupvar='group_id')
def delete_group(group_id):
    group = PostGroup.query.filter_by(id=group_id).first_or_404()

    form = ConfirmationForm()
    if form.validate_on_submit():
        if form.sure.data:
            for gm in group.memberships:
                db.session.delete(gm)
            db.session.delete(group)
            flash('Group %s has been deleted' % (group.groupname, ))
            return redirect(url_for('main.user', username=current_user.username))
        else:
            return redirect(url_for('.group', id=group_id))

    return render_template('groups/delete_group.html', form=form)

@groups.route('/add-group-members/<int:group_id>', methods=['GET', 'POST'])
@login_required
@group_permission_required(Permission.ADMINISTER, groupvar='group_id')
def add_group_members(group_id):

    form = AddMembersForm(group_id)
    if form.validate_on_submit():
        for invitee in map(lambda x: x.strip(), form.invites.data.split(',')):
            with db.session.no_autoflush:
                kwargs = {'group_id':group_id}
                user_exists = False
                if '@' in invitee:
                    kwargs['email'] = invitee
                else:
                    user = User.query.filter_by(username=invitee)
                    user = user.first_or_404()
                    kwargs['email'] = user.email
                    kwargs['user_id'] = user.id
                    user_exists = True

                gi = GroupInvite(**kwargs)
                if user_exists:
                    send_email(user.email, 'You have been invited to join %s at Labloid' % (form.group.groupname, ),
                               'groups/email/confirm', user=user, other=current_user, group=gi.group)
                else:
                    send_email(kwargs['email'], 'You have been invited to join Labloid',
                               'auth/email/invitation', user=current_user, token=gi.generate_confirmation_token())

                flash('A invitation to join %s has been sent out.' % (form.group.groupname, ))
                db.session.add(gi)

            db.session.commit()

        return redirect(url_for('.group', id=form.group.id))
    return render_template('groups/add_members.html', form=form)



@groups.route('/confirm-group/<token>')
def confirm_group(token):
    if GroupInvite.confirm(token, current_user):
        flash('Groupmembership confirmed!')
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('main.user', username=current_user.username))

@groups.route('/decline-invite/<token>')
def decline_invite(token):
    if GroupInvite.decline(token):
        flash('Invite declined!')
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('main.user', username=current_user.username))