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
static unsigned int test_peer_fd_checks;

static BOOL
test_peer_check_fd(freerdp_peer *client)
{
	(void)client;
	test_peer_fd_checks++;
	return TRUE;
}

ZUC_TEST(rdp_channels, licensing_does_not_pump_vcm)
{
	struct rdp_backend backend = { 0 };
	RdpPeerContext context = { 0 };
	freerdp_peer peer = { 0 };

	context.rdpBackend = &backend;
	/* This sentinel must never reach the FreeRDP VCM before activation. */
	context.vcm = (HANDLE)(uintptr_t)1;
	peer.context = (rdpContext *)&context;
	peer.CheckFileDescriptor = test_peer_check_fd;
	peer.activated = FALSE;
	test_peer_fd_checks = 0;

	ZUC_ASSERT_EQ(0, rdp_client_activity(-1, WL_EVENT_READABLE, &peer));
	ZUC_ASSERT_EQ(1, test_peer_fd_checks);

	/* The peer transport is still pumped when VCM is absent. */
	context.vcm = NULL;
	peer.activated = TRUE;
	ZUC_ASSERT_EQ(0, rdp_client_activity(-1, WL_EVENT_READABLE, &peer));
	ZUC_ASSERT_EQ(2, test_peer_fd_checks);
}

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

static DISPLAY_CONTROL_MONITOR_LAYOUT
valid_desktop_layout(void)
{
	DISPLAY_CONTROL_MONITOR_LAYOUT monitor = {
		.Flags = DISPLAY_CONTROL_MONITOR_PRIMARY,
		.Width = 1024, .Height = 768,
		.DesktopScaleFactor = 100, .DeviceScaleFactor = 100,
	};
	return monitor;
}

ZUC_TEST(rdp_display, invalid_desktop_layout_is_rejected)
{
	struct rdp_backend backend = { 0 };
	RdpPeerContext peer_ctx = { 0 };
	freerdp_peer peer = { 0 };
	DispServerContext disp = { 0 };
	DISPLAY_CONTROL_MONITOR_LAYOUT monitor = valid_desktop_layout();
	DISPLAY_CONTROL_MONITOR_LAYOUT_PDU pdu = {
		.MonitorLayoutSize = DISPLAY_CONTROL_MONITOR_LAYOUT_SIZE,
		.NumMonitors = 1, .Monitors = &monitor,
	};

	/* Run as the channel thread, without a dispatcher: invalid input must not queue. */
	backend.compositor_tid = 0;
	peer_ctx.rdpBackend = &backend;
	peer.context = (rdpContext *)&peer_ctx;
	disp.custom = &peer;
	ZUC_ASSERT_TRUE(rdp_desktop_layout_valid(&pdu));
	ZUC_ASSERT_FALSE(rdp_desktop_layout_valid(NULL));
	pdu.NumMonitors = 2;
	ZUC_ASSERT_EQ(ERROR_INVALID_DATA, rdp_desktop_layout_received(&disp, &pdu));
	pdu.NumMonitors = 0;
	ZUC_ASSERT_EQ(ERROR_INVALID_DATA, rdp_desktop_layout_received(&disp, &pdu));
	pdu.NumMonitors = 1;
	pdu.MonitorLayoutSize = 0;
	ZUC_ASSERT_EQ(ERROR_INVALID_DATA, rdp_desktop_layout_received(&disp, &pdu));
	pdu.MonitorLayoutSize = DISPLAY_CONTROL_MONITOR_LAYOUT_SIZE;
	pdu.Monitors = NULL;
	ZUC_ASSERT_EQ(ERROR_INVALID_DATA, rdp_desktop_layout_received(&disp, &pdu));
	pdu.Monitors = &monitor;

	monitor.Flags = 0;
	ZUC_ASSERT_EQ(ERROR_INVALID_DATA, rdp_desktop_layout_received(&disp, &pdu));
	monitor = valid_desktop_layout();
	monitor.Left = -1;
	ZUC_ASSERT_EQ(ERROR_INVALID_DATA, rdp_desktop_layout_received(&disp, &pdu));
	monitor = valid_desktop_layout();
	monitor.Width = 199;
	ZUC_ASSERT_EQ(ERROR_INVALID_DATA, rdp_desktop_layout_received(&disp, &pdu));
	monitor.Width = 8193;
	ZUC_ASSERT_EQ(ERROR_INVALID_DATA, rdp_desktop_layout_received(&disp, &pdu));
	monitor = valid_desktop_layout();
	monitor.Height = UINT32_MAX;
	ZUC_ASSERT_EQ(ERROR_INVALID_DATA, rdp_desktop_layout_received(&disp, &pdu));
	monitor = valid_desktop_layout();
	monitor.Orientation = 1;
	ZUC_ASSERT_EQ(ERROR_INVALID_DATA, rdp_desktop_layout_received(&disp, &pdu));
	monitor = valid_desktop_layout();
	monitor.DesktopScaleFactor = 99;
	ZUC_ASSERT_EQ(ERROR_INVALID_DATA, rdp_desktop_layout_received(&disp, &pdu));
	monitor.DesktopScaleFactor = 501;
	ZUC_ASSERT_EQ(ERROR_INVALID_DATA, rdp_desktop_layout_received(&disp, &pdu));
	monitor = valid_desktop_layout();
	monitor.DeviceScaleFactor = 101;
	ZUC_ASSERT_EQ(ERROR_INVALID_DATA, rdp_desktop_layout_received(&disp, &pdu));
}

ZUC_TEST(rdp_display, fixed_desktop_ignores_client_layout)
{
	struct rdp_backend backend = { 0 };
	RdpPeerContext peer_ctx = { 0 };
	freerdp_peer peer = { 0 };
	DispServerContext disp = { 0 };
	DISPLAY_CONTROL_MONITOR_LAYOUT monitor = valid_desktop_layout();
	DISPLAY_CONTROL_MONITOR_LAYOUT_PDU pdu = {
		.MonitorLayoutSize = DISPLAY_CONTROL_MONITOR_LAYOUT_SIZE,
		.NumMonitors = 1, .Monitors = &monitor,
	};

	backend.no_clients_resize = true;
	backend.compositor_tid = 0;
	peer_ctx.rdpBackend = &backend;
	peer.context = (rdpContext *)&peer_ctx;
	disp.custom = &peer;
	/* No VCM, settings, dispatcher or output exists. Ignoring must touch none. */
	ZUC_ASSERT_EQ(CHANNEL_RC_OK, rdp_desktop_layout_received(&disp, &pdu));
}

ZUC_TEST(rdp_display, desktop_layout_snapshot_and_teardown)
{
	struct rdp_backend backend = { 0 };
	RdpPeerContext peer_ctx = { 0 };
	freerdp_peer peer = { 0 };
	DispServerContext disp = { 0 };
	rdpSettings *settings = freerdp_settings_new(TRUE);
	struct rdp_loop_task *base;
	struct rdp_desktop_layout_task *task;
	DISPLAY_CONTROL_MONITOR_LAYOUT monitor = valid_desktop_layout();
	DISPLAY_CONTROL_MONITOR_LAYOUT_PDU pdu = {
		.MonitorLayoutSize = DISPLAY_CONTROL_MONITOR_LAYOUT_SIZE,
		.NumMonitors = 1, .Monitors = &monitor,
	};

	ZUC_ASSERT_NOT_NULL(settings);
	backend.compositor_tid = 0;
	peer_ctx.rdpBackend = &backend;
	peer_ctx._p.settings = settings;
	peer.context = (rdpContext *)&peer_ctx;
	disp.custom = &peer;
	wl_list_init(&peer_ctx.loop_task_list);
	ZUC_ASSERT_EQ(0, pthread_mutex_init(&peer_ctx.loop_task_list_mutex, NULL));
	peer_ctx.loop_task_event_source_fd = eventfd(0, EFD_CLOEXEC | EFD_SEMAPHORE);
	ZUC_ASSERT_TRUE(peer_ctx.loop_task_event_source_fd >= 0);

	ZUC_ASSERT_EQ(CHANNEL_RC_OK, rdp_desktop_layout_received(&disp, &pdu));
	monitor.Width = 4096;
	monitor.Height = 2160;
	base = wl_container_of(peer_ctx.loop_task_list.next, base, link);
	task = wl_container_of(base, task, base);
	ZUC_ASSERT_EQ(1024, task->monitor.width);
	ZUC_ASSERT_EQ(768, task->monitor.height);
	ZUC_ASSERT_TRUE(task->monitor.is_primary);
	wl_list_remove(&base->link);
	ZUC_ASSERT_TRUE(wl_list_empty(&peer_ctx.loop_task_list));

	/* Simulate destruction before the queued callback; freeOnly cannot dereference it. */
	base->peerCtx = (RdpPeerContext *)(uintptr_t)1;
	base->func(true, base);
	close(peer_ctx.loop_task_event_source_fd);
	pthread_mutex_destroy(&peer_ctx.loop_task_list_mutex);
	freerdp_settings_free(settings);
}
