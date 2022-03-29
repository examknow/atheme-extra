#include "fn-compat.h"
#include "atheme.h"
#include "projectns.h"

static void
do_sethost(struct user *u, stringref host)
{
	if (!strcmp(u->vhost, host))
		return;

	user_sethost(nicksvs.me->me, u, host);
}

static void
do_sethost_all(struct myuser *mu, stringref host)
{
	mowgli_node_t *n;
	struct user *u;

	MOWGLI_ITER_FOREACH(n, mu->logins.head)
	{
		u = n->data;

		do_sethost(u, host ? host : u->host);
	}
}

static void
remove_request_from_list(mowgli_node_t *const restrict n)
{
	struct cloak_request *request = n->data;

	mowgli_node_delete(n, &projectsvs->cloak_requests);
	mowgli_node_free(n);

	free(request);
}

static void
ps_cmd_request(struct sourceinfo *si, int parc, char *parv[])
{
	char *target = parv[0];
	char *cloak  = parv[1];

	if (!target || !cloak)
	{
		command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "REQUEST");
		command_fail(si, fault_needmoreparams, _("Syntax: REQUEST <account> <cloak>"));
		return;
	}

	char *namespace = strtok(sstrdup(cloak), "/");
	struct projectns *project = mowgli_patricia_retrieve(projectsvs->projects_by_cloakns, namespace);

	struct myuser *tmu = myuser_find_ext(target);

	if (!tmu)
	{
		command_fail(si, fault_nosuch_target, _("\2%s\2 is not registered."), target);
		return;
	}

	if (!project)
	{
		command_fail(si, fault_nosuch_target, _("The \2%s\2 namespace is not registered to a project."), namespace);
		return;
	}

	mowgli_node_t *n;
	bool is_gc = false;
	MOWGLI_ITER_FOREACH(n, project->contacts.head)
	{
		struct project_contact *contact = n->data;
		if (si->smu == contact->mu)
		{
			is_gc = true;
			break;
		}
	}

	if (!is_gc)
	{
		command_fail(si, fault_noprivs, _("You are not an authorized group contact for the \2%s\2 namespace."), namespace);
		return;
	}

	if (!check_vhost_validity(si, cloak))
		return;

	if (metadata_find(tmu, "private:freeze:freezer"))
	{
		command_fail(si, fault_nochange, _("\2%s\2 is frozen and cannot be cloaked."), entity(tmu)->name);
		return;
	}

	struct metadata *md = metadata_find(tmu, "private:usercloak");
	if (md != NULL && !strcmp(md->value, cloak))
	{
		command_fail(si, fault_nochange, _("\2%s\2 already has the given cloak set."), entity(tmu)->name);
		return;
	}

	struct cloak_request *request;
	request = smalloc(sizeof *request);
	request->project = project->name;
	request->requestor = entity(si->smu)->name;
	request->target = entity(tmu)->name;
	request->cloak = sstrdup(cloak);
	mowgli_node_add(request, mowgli_node_create(), &projectsvs->cloak_requests);

	command_success_nodata(si, _("Cloak \2%s\2 requested for \2%s\2 on behalf of the \2%s\2 project"), cloak, entity(tmu)->name, project->name);
	logcommand(si, CMDLOG_REQUEST, "REQUEST: \2%s\2 for \2%s\2 (project: \2%s\2)", cloak, entity(tmu)->name, project->name);
}

static void
ps_cmd_waiting(struct sourceinfo *si, int parc, char *parv[])
{
	struct cloak_request *request;
	mowgli_node_t *n;

	int i = 1;
	MOWGLI_ITER_FOREACH(n, projectsvs->cloak_requests.head)
	{
		request = n->data;
		command_success_nodata(si,
			_("#%d: account: \2%s\2, cloak: \2%s\2, project: \2%s\2 (requested by \2%s\2)"),
			i, request->target, request->cloak, request->project, request->requestor);
		i++;
	}
	command_success_nodata(si, _("End of list."));
	logcommand(si, CMDLOG_GET, "WAITING");
}

static void
ps_cmd_activate(struct sourceinfo *si, int parc, char *parv[])
{
	struct cloak_request *request;
	mowgli_node_t *n;
	char *target = parv[0];

	if (!target)
	{
		command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "ACTIVATE");
		command_fail(si, fault_needmoreparams, _("Syntax: ACTIVATE <account>"));
		return;
	}

	MOWGLI_ITER_FOREACH(n, projectsvs->cloak_requests.head)
	{
		request = n->data;
		int i = 1;
		if (!strcmp(target, request->target) || atoi(target) == i)
		{
			char timestring[16];
			struct myuser *tmu = myuser_find_ext(request->target);
			snprintf(timestring, 16, "%lu", (unsigned long)time(NULL));
			metadata_add(tmu, "private:usercloak", request->cloak);
			metadata_add(tmu, "private:usercloak-timestamp", timestring);
			metadata_add(tmu, "private:usercloak-assigner", get_source_name(si));
			do_sethost_all(tmu, request->cloak);
			logcommand(si, CMDLOG_ADMIN, "ACTIVATE: \2%s\2 for \2%s\2 (requested by: \2%s\2)", request->cloak, entity(tmu)->name, request->requestor);
			command_success_nodata(si, _("Set vHost for \2%s\2 to \2%s\2"), entity(tmu)->name, request->cloak);
			remove_request_from_list(n);
			return;
		}
		i++;
	}
	command_fail(si, fault_nosuch_target, _("\2%s\2 not found in cloak request database."), target);
}

static void
ps_cmd_reject(struct sourceinfo *si, int parc, char *parv[])
{
	struct cloak_request *request;
	mowgli_node_t *n;
	char *target = parv[0];

	if (!target)
	{
		command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "REJECT");
		command_fail(si, fault_needmoreparams, _("Syntax: REJECT <account>"));
		return;
	}

	MOWGLI_ITER_FOREACH(n, projectsvs->cloak_requests.head)
	{
		request = n->data;
		int i = 1;
		if (!strcmp(target, request->target) || atoi(target) == i)
		{
			struct myuser *tmu = myuser_find_ext(request->target);
			logcommand(si, CMDLOG_ADMIN, "REJECT: \2%s\2 for \2%s\2 (requested by: \2%s\2)", request->cloak, entity(tmu)->name, request->requestor);
			command_success_nodata(si, _("Cloak request for \2%s\2 has been rejected"), entity(tmu)->name);
			remove_request_from_list(n);
			return;
		}
		i++;
	}
	command_fail(si, fault_nosuch_target, _("\2%s\2 not found in cloak request database."), target);
}

static struct command ps_request = {
	.name		= "REQUEST",
	.desc		= N_("Requests new project cloak for a user."),
	.access		= AC_AUTHENTICATED,
	.maxparc	= 2,
	.cmd		= &ps_cmd_request,
	.help		= { .path = "freenode/project_request" },
};

static struct command ps_waiting = {
	.name		= "WAITING",
	.desc		= N_("Lists cloak requests currently waiting for activation."),
	.access		= PRIV_PROJECT_ADMIN,
	.maxparc	= 1,
	.cmd		= &ps_cmd_waiting,
	.help		= { .path = "freenode/project_waiting" },
};

static struct command ps_activate = {
	.name		= "ACTIVATE",
	.desc		= N_("Activates a pending cloak request."),
	.access		= PRIV_PROJECT_ADMIN,
	.maxparc	= 1,
	.cmd		= &ps_cmd_activate,
	.help		= { .path = "freenode/project_activate" },
};

static struct command ps_reject = {
	.name		= "REJECT",
	.desc		= N_("Reject a pending cloak request."),
	.access		= PRIV_PROJECT_ADMIN,
	.maxparc	= 1,
	.cmd		= &ps_cmd_reject,
	.help		= { .path = "freenode/project_reject" },
};

static void
mod_init(struct module *const restrict m)
{
	if (!use_projectns_main_symbols(m))
		return;
	service_named_bind_command("projectserv", &ps_request);
	service_named_bind_command("projectserv", &ps_waiting);
	service_named_bind_command("projectserv", &ps_activate);
	service_named_bind_command("projectserv", &ps_reject);
}

static void mod_deinit(const module_unload_intent_t unused)
{
	service_named_unbind_command("projectserv", &ps_request);
	service_named_unbind_command("projectserv", &ps_waiting);
	service_named_unbind_command("projectserv", &ps_activate);
	service_named_unbind_command("projectserv", &ps_reject);
}

DECLARE_MODULE_V1
(
	"freenode/projectns/cloakrequest", MODULE_UNLOAD_CAPABILITY_OK, mod_init, mod_deinit,
	"", "freenode <http://www.freenode.net>"
);
