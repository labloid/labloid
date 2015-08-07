from flask import render_template, redirect, url_for, abort, flash, request, \
    current_app, make_response
from flask.ext.login import login_required, current_user
from flask.ext.sqlalchemy import get_debug_queries
from . import main
from .forms import EditProfileForm, EditProfileAdminForm, PostForm, \
    CommentForm, GroupForm, EditMemberShipForm, AddMembersForm
from .. import db
from ..models import Permission, GroupRole, User, Post, Comment, PostGroup, GroupMemberShip
from ..decorators import admin_required, permission_required
from .errors import forbidden


@main.after_app_request
def after_request(response):
    for query in get_debug_queries():
        if query.duration >= current_app.config['LABLOID_SLOW_DB_QUERY_TIME']:
            current_app.logger.warning(
                'Slow query: %s\nParameters: %s\nDuration: %fs\nContext: %s\n'
                % (query.statement, query.parameters, query.duration,
                   query.context))
    return response


@main.route('/', methods=['GET', 'POST'])
def index():
    page = request.args.get('page', 1, type=int)
    show_followed = False
    if current_user.is_authenticated():
        show_followed = bool(request.cookies.get('show_followed', ''))
    if show_followed:
        query = current_user.my_articles

    return render_template('index.html', show_followed=show_followed)


@main.route('/user/<username>')
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    page = request.args.get('page', 1, type=int)
    pagination = user.posts.order_by(Post.timestamp.desc()).paginate(
        page, per_page=current_app.config['LABLOID_POSTS_PER_PAGE'],
        error_out=False)
    posts = pagination.items
    return render_template('user.html', user=user, posts=posts,
                           pagination=pagination)


@main.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        db.session.add(current_user)
        flash('Your profile has been updated.')
        return redirect(url_for('.user', username=current_user.username))
    form.name.data = current_user.name
    return render_template('edit_profile.html', form=form)


@main.route('/edit-membership/<int:user_id>/<int:group_id>', methods=['GET', 'POST'])
@login_required
def edit_membership(user_id, group_id):

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


@main.route('/group/<int:id>',  methods=['GET', 'POST'])
@login_required
def group(id):
    group = PostGroup.query.filter_by(id=id).first_or_404()
    if not current_user.is_member_of(group):
        return forbidden('You do not have the rights to see this group!')

    form = AddMembersForm(group_id=id)
    if form.validate_on_submit():

        with db.session.no_autoflush:

            for invitee in map(lambda x: x.strip(), form.invites.data.split(',')):
                if '@' in invitee:
                    user = User.query.filter_by(email=invitee)
                else:
                    user = User.query.filter_by(username=invitee)

                if user.count() > 0:
                    user = user.first_or_404()
                    gm = GroupMemberShip()
                    gm.group = form.group
                    gm.role = GroupRole.query.filter_by(name='Reader').first_or_404()
                    user.groupmemberships.append(gm)
                    flash('%s has been added to %s' % (user.username, group.groupname))
                    db.session.add(gm)
                else:
                    pass
                    # TODO send out email
            db.session.commit()

    return render_template('group.html', group=group, me=current_user, form=form)


@main.route('/create-group', methods=['GET', 'POST'])
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
        return redirect(url_for('.user', username=current_user.username))
    return render_template('add_group.html', form=form)

#
# @main.route('/edit-profile/<int:id>', methods=['GET', 'POST'])
# @login_required
# @admin_required
# def edit_profile_admin(id):
#     user = User.query.get_or_404(id)
#     form = EditProfileAdminForm(user=user)
#     if form.validate_on_submit():
#         user.email = form.email.data
#         user.username = form.username.data
#         user.confirmed = form.confirmed.data
#         user.role = GroupRole.query.get(form.role.data)
#         user.name = form.name.data
#         user.location = form.location.data
#         user.about_me = form.about_me.data
#         db.session.add(user)
#         flash('The profile has been updated.')
#         return redirect(url_for('.user', username=user.username))
#     form.email.data = user.email
#     form.username.data = user.username
#     form.confirmed.data = user.confirmed
#     form.role.data = user.role_id
#     form.name.data = user.name
#     form.location.data = user.location
#     form.about_me.data = user.about_me
#     return render_template('edit_profile.html', form=form, user=user)
#
#
# @main.route('/post/<int:id>', methods=['GET', 'POST'])
# def post(id):
#     post = Post.query.get_or_404(id)
#     form = CommentForm()
#     if form.validate_on_submit():
#         comment = Comment(body=form.body.data,
#                           post=post,
#                           author=current_user._get_current_object())
#         db.session.add(comment)
#         flash('Your comment has been published.')
#         return redirect(url_for('.post', id=post.id, page=-1))
#     page = request.args.get('page', 1, type=int)
#     if page == -1:
#         page = (post.comments.count() - 1) / \
#             current_app.config['FLASKY_COMMENTS_PER_PAGE'] + 1
#     pagination = post.comments.order_by(Comment.timestamp.asc()).paginate(
#         page, per_page=current_app.config['FLASKY_COMMENTS_PER_PAGE'],
#         error_out=False)
#     comments = pagination.items
#     return render_template('post.html', posts=[post], form=form,
#                            comments=comments, pagination=pagination)
#
#
# @main.route('/edit/<int:id>', methods=['GET', 'POST'])
# @login_required
# def edit(id):
#     post = Post.query.get_or_404(id)
#     if current_user != post.author and \
#             not current_user.can(Permission.ADMINISTER):
#         abort(403)
#     form = PostForm()
#     if form.validate_on_submit():
#         post.body = form.body.data
#         db.session.add(post)
#         flash('The post has been updated.')
#         return redirect(url_for('.post', id=post.id))
#     form.body.data = post.body
#     return render_template('edit_post.html', form=form)
#
# #
# # @main.route('/follow/<username>')
# # @login_required
# # @permission_required(Permission.FOLLOW)
# # def follow(username):
# #     user = User.query.filter_by(username=username).first()
# #     if user is None:
# #         flash('Invalid user.')
# #         return redirect(url_for('.index'))
# #     if current_user.is_reader_of(user):
# #         flash('You are already following this user.')
# #         return redirect(url_for('.user', username=username))
# #     current_user.add_to_feed(user)
# #     flash('You are now following %s.' % username)
# #     return redirect(url_for('.user', username=username))
#
#
# @main.route('/unfollow/<username>')
# @login_required
# @permission_required(Permission.FOLLOW)
# def unfollow(username):
#     user = User.query.filter_by(username=username).first()
#     if user is None:
#         flash('Invalid user.')
#         return redirect(url_for('.index'))
#     if not current_user.is_reader_of(user):
#         flash('You are not following this user.')
#         return redirect(url_for('.user', username=username))
#     current_user.leave_feed(user)
#     flash('You are not following %s anymore.' % username)
#     return redirect(url_for('.user', username=username))
#
#
# @main.route('/followers/<username>')
# def followers(username):
#     user = User.query.filter_by(username=username).first()
#     if user is None:
#         flash('Invalid user.')
#         return redirect(url_for('.index'))
#     page = request.args.get('page', 1, type=int)
#     pagination = user.followers.paginate(
#         page, per_page=current_app.config['LABLOID_FOLLOWERS_PER_PAGE'],
#         error_out=False)
#     follows = [{'user': item.follower, 'timestamp': item.timestamp}
#                for item in pagination.items]
#     return render_template('followers.html', user=user, title="Followers of",
#                            endpoint='.followers', pagination=pagination,
#                            follows=follows)

#
# @main.route('/followed-by/<username>')
# def followed_by(username):
#     user = User.query.filter_by(username=username).first()
#     if user is None:
#         flash('Invalid user.')
#         return redirect(url_for('.index'))
#     page = request.args.get('page', 1, type=int)
#     pagination = user.followed.paginate(
#         page, per_page=current_app.config['FLASKY_FOLLOWERS_PER_PAGE'],
#         error_out=False)
#     follows = [{'user': item.followed, 'timestamp': item.timestamp}
#                for item in pagination.items]
#     return render_template('followers.html', user=user, title="Followed by",
#                            endpoint='.followed_by', pagination=pagination,
#                            follows=follows)
#
#
# @main.route('/all')
# @login_required
# def show_all():
#     resp = make_response(redirect(url_for('.index')))
#     resp.set_cookie('show_followed', '', max_age=30*24*60*60)
#     return resp
#
#
# @main.route('/followed')
# @login_required
# def show_followed():
#     resp = make_response(redirect(url_for('.index')))
#     resp.set_cookie('show_followed', '1', max_age=30*24*60*60)
#     return resp
#
#
# @main.route('/moderate')
# @login_required
# @permission_required(Permission.MODERATE_COMMENTS)
# def moderate():
#     page = request.args.get('page', 1, type=int)
#     pagination = Comment.query.order_by(Comment.timestamp.desc()).paginate(
#         page, per_page=current_app.config['FLASKY_COMMENTS_PER_PAGE'],
#         error_out=False)
#     comments = pagination.items
#     return render_template('moderate.html', comments=comments,
#                            pagination=pagination, page=page)
#
#
# @main.route('/moderate/enable/<int:id>')
# @login_required
# @permission_required(Permission.MODERATE_COMMENTS)
# def moderate_enable(id):
#     comment = Comment.query.get_or_404(id)
#     comment.disabled = False
#     db.session.add(comment)
#     return redirect(url_for('.moderate',
#                             page=request.args.get('page', 1, type=int)))
#
#
# @main.route('/moderate/disable/<int:id>')
# @login_required
# @permission_required(Permission.MODERATE_COMMENTS)
# def moderate_disable(id):
#     comment = Comment.query.get_or_404(id)
#     comment.disabled = True
#     db.session.add(comment)
#     return redirect(url_for('.moderate',
#                             page=request.args.get('page', 1, type=int)))
