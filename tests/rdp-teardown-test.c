#include "config.h"

#include "zunitc/zunitc.h"

#include "../libweston/backend-rdp/rdp.c"

ZUC_TEST(rdp_teardown, activation_error_cleanup)
{
	struct weston_compositor compositor = { 0 };
	struct weston_rdprail_shell_api shell_api = { 0 };
	struct rdp_backend backend = { 0 };
	RdpPeerContext context = { 0 };
	rdpSettings settings = { 0 };
	freerdp_peer peer = { 0 };

	compositor.state = WESTON_COMPOSITOR_SLEEPING;
	backend.compositor = &compositor;
	backend.compositor_tid = rdp_get_tid();
	backend.rdprail_shell_api = &shell_api;
	backend.rdp_peer = &peer;
	context.rdpBackend = &backend;
	context._p.settings = &settings;
	peer.context = (rdpContext *)&context;
	settings.SurfaceCommandsEnabled = TRUE;
	settings.RemoteApplicationMode = TRUE;
	settings.HiDefRemoteApp = TRUE;
	settings.DesktopWidth = 800;
	settings.DesktopHeight = 600;
	ZUC_ASSERT_TRUE(rdp_peer_context_new(&peer, &context));
	wl_list_init(&context.item.link);
	ZUC_ASSERT_EQ(0, pthread_mutex_init(&context.loop_task_list_mutex, NULL));
	ZUC_ASSERT_TRUE(rdp_rail_peer_init(&peer, &context));

	ZUC_ASSERT_FALSE(xf_peer_activate(&peer));
	rdp_peer_context_free(&peer, &context);
	ZUC_ASSERT_FALSE(backend.rdp_peer);
}

#if FREERDP_VERSION_MAJOR >= 3
static int
test_log_handler(const char *fmt, va_list ap)
{
	return vfprintf(stderr, fmt, ap);
}

ZUC_TEST(rdp_authentication, nla_only_policy)
{
	rdpContext context = { 0 };
	freerdp_peer peer = { 0 };
	rdpSettings *settings = freerdp_settings_new(TRUE);

	ZUC_ASSERT_NOT_NULL(settings);
	context.settings = settings;
	peer.context = &context;

	ZUC_ASSERT_TRUE(rdp_peer_configure_nla(&peer, "/run/secrets/test-rdp.sam"));
	ZUC_ASSERT_TRUE(freerdp_settings_get_bool(settings, FreeRDP_NlaSecurity));
	ZUC_ASSERT_TRUE(freerdp_settings_get_bool(settings, FreeRDP_Authentication));
	ZUC_ASSERT_FALSE(freerdp_settings_get_bool(settings, FreeRDP_TlsSecurity));
	ZUC_ASSERT_FALSE(freerdp_settings_get_bool(settings, FreeRDP_RdpSecurity));
	ZUC_ASSERT_STREQ("/run/secrets/test-rdp.sam",
		freerdp_settings_get_string(settings, FreeRDP_NtlmSamFile));
	ZUC_ASSERT_FALSE(peer.Logon(&peer, NULL, FALSE));
	weston_log_set_handler(test_log_handler, test_log_handler);
	ZUC_ASSERT_TRUE(peer.Logon(&peer, NULL, TRUE));
	freerdp_settings_free(settings);
}

ZUC_TEST(rdp_authentication, unconfigured_policy_preserves_wslg)
{
	rdpContext context = { 0 };
	freerdp_peer peer = { 0 };
	rdpSettings *settings = freerdp_settings_new(TRUE);

	ZUC_ASSERT_NOT_NULL(settings);
	context.settings = settings;
	peer.context = &context;
	ZUC_ASSERT_TRUE(rdp_peer_configure_nla(&peer, NULL));
	ZUC_ASSERT_TRUE(rdp_peer_configure_nla(&peer, ""));
	ZUC_ASSERT_NULL(peer.Logon);
	ZUC_ASSERT_NULL(freerdp_settings_get_string(settings, FreeRDP_NtlmSamFile));
	freerdp_settings_free(settings);
}
#endif
