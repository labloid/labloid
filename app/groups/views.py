from flask import render_template, redirect, url_for, abort, flash, request, \
    current_app, make_response
from flask.ext.login import login_required, current_user
from flask.ext.sqlalchemy import get_debug_queries
from . import groups
from .forms import GroupForm, EditMemberShipForm, AddMembersForm, DeleteGroupForm
from .. import db
from ..models import Permission, GroupRole, User, Post, Comment, PostGroup, GroupMemberShip
from .errors import forbidden
from .decorators import group_permission_required

@groups.route('/edit-membership/<int:user_id>/<int:group_id>', methods=['GET', 'POST'])
@login_required
def edit_membership(user_id, group_id):
    # if user_id = my_id add a leave group but only if I am not the owner and if there are other owners
    # if user_id ~= my_id only delete users if I can administer
    # Only allow to change the role if I can administer
    # invite more members only if I can administer
    # if I am owner or admin, delete group

    ms = GroupMemberShip.query.filter_by(member_id=user_id, group_id=group_id).first_or_404()
    if not ms.group.is_administrator(current_user):
        return forbidden('You do not have the rights to edit this group!')

    form = EditMemberShipForm(user_id=user_id, group_id=group_id)

    if form.validate_on_submit():
        if form.cancel.data:
            return redirect(url_for('.group', id=group_id))
        elif form.submit.data:
            ms.role = GroupRole.query.get(form.role.data)
            db.session.add(ms)
            flash("%s's role has been updated to %s" % (ms.user.username, form.choice_map[form.role.data]))
            return redirect(url_for('.group', id=group_id))
        elif form.delete.data:
            # TODO: implement delete confirmation
            db.session.delete(ms)
            flash("User %s has been removed from %s" % (ms.user.username, ms.group.groupname))
            return redirect(url_for('.group', id=group_id))

    return render_template('edit_membership.html', form=form)


@groups.route('/group/<int:id>',  methods=['GET', 'POST'])
@login_required
def group(id):
    group = PostGroup.query.filter_by(id=id).first_or_404()
    if not current_user.is_member_of(group):
        return forbidden('You do not have the rights to see this group!')

    # form = AddMembersForm(group_id=id)
    # if form.validate_on_submit():
    #
    #     with db.session.no_autoflush:
    #
    #         for invitee in map(lambda x: x.strip(), form.invites.data.split(',')):
    #             if '@' in invitee:
    #                 user = User.query.filter_by(email=invitee)
    #             else:
    #                 user = User.query.filter_by(username=invitee)
    #
    #             if user.count() > 0:
    #                 user = user.first_or_404()
    #                 gm = GroupMemberShip()
    #                 gm.group = form.group
    #                 gm.role = GroupRole.query.filter_by(name='Reader').first_or_404()
    #                 user.groupmemberships.append(gm)
    #                 flash('%s has been added to %s' % (user.username, group.groupname))
    #                 db.session.add(gm)
    #             else:
    #                 pass
    #                 # TODO send out email
    #         db.session.commit()

    return render_template('groups/group.html', group=group, me=current_user)


@groups.route('/create-group', methods=['GET', 'POST'])
@login_required
def create_group():
    form = GroupForm(current_user)
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

        with db.session.no_autoflush:

            for invitee in map(lambda x: x.strip(), form.invites.data.split(',')):
                if '@' in invitee:
                    user = User.query.filter_by(email=invitee)
                else:
                    user = User.query.filter_by(username=invitee)

                if user.count() > 0:
                    user = user.first_or_404()
                    gm = GroupMemberShip()
                    gm.group = pg
                    gm.role = GroupRole.query.filter_by(name='Reader').first_or_404()
                    user.groupmemberships.append(gm)
                    flash('%s has been added to %s' % (user.username, form.groupname.data))

                    db.session.add(gm)
                else:
                    pass
                    # TODO send out email
            db.session.commit()

        # TODO: handle invites for group with email

        flash('Group %s has been created' % (form.groupname.data,))
        return redirect(url_for('main.user', username=current_user.username))
    return render_template('groups/add_group.html', form=form)

@groups.route('/delete-group/<int:group_id>', methods=['GET', 'POST'])
@login_required
@group_permission_required(Permission.ADMINISTER, groupvar='group_id')
def delete_group(group_id):
    group = PostGroup.query.filter_by(id=group_id).first_or_404()
    if not group.is_administrator(current_user):
        flash('Only Owners can delete a group.')
        return redirect(request.referrer or url_for('index'))

    form = DeleteGroupForm()
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
