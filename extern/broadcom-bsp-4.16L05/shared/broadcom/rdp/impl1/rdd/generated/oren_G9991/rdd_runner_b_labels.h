#ifndef RUNNER_B_CODE_ADDRESSES
#define RUNNER_B_CODE_ADDRESSES

#define runner_b_start_task_initialization_task		(0x14)
#define runner_b_initialization_task		(0x14)
#define runner_b_start_task_timer_scheduler_set		(0x35A8)
#define runner_b_timer_scheduler_set		(0x35A8)
#define runner_b_start_task_cpu_rx_wakeup_request		(0x24A4)
#define runner_b_cpu_rx_wakeup_request		(0x24A4)
#define runner_b_start_task_cpu_tx_wakeup_request		(0x2C3C)
#define runner_b_cpu_tx_wakeup_request		(0x2C3C)
#define runner_b_start_task_local_switching_multicast_wakeup_request		(0x3154)
#define runner_b_local_switching_multicast_wakeup_request		(0x3154)
#define runner_b_start_task_policer_budget_allocator_1st_wakeup_request		(0x3E14)
#define runner_b_policer_budget_allocator_1st_wakeup_request		(0x3E14)
#define runner_b_start_task_rate_control_budget_allocator_1st_wakeup_request		(0x2B1C)
#define runner_b_rate_control_budget_allocator_1st_wakeup_request		(0x2B1C)
#define runner_b_start_task_upstream_vlan_wakeup_request		(0x408)
#define runner_b_upstream_vlan_wakeup_request		(0x408)
#define runner_b_start_task_wan_interworking_wakeup_request		(0x14F4)
#define runner_b_wan_interworking_wakeup_request		(0x14F4)
#define runner_b_start_task_wan_to_wan_wakeup_request		(0x204)
#define runner_b_wan_to_wan_wakeup_request		(0x204)
#define runner_b_start_task_smart_card_send_and_recieve		(0x3720)
#define runner_b_smart_card_send_and_recieve		(0x3720)
#define runner_b_start_task_wan_tx_wakeup_request		(0x1C08)
#define runner_b_wan_tx_wakeup_request		(0x1C08)
#define runner_b_start_task_epon_tx_request_wakeup_request		(0x3EE0)
#define runner_b_epon_tx_request_wakeup_request		(0x3EE0)
#define runner_b_start_task_debug_routine		(0x11C)
#define runner_b_debug_routine		(0x11C)
#define runner_b_vlan_command_transparent		(0xC34)
#define runner_b_vlan_command_add_outer_tag		(0xC58)
#define runner_b_vlan_command_add_always		(0xCCC)
#define runner_b_vlan_command_add_3rd_tag		(0xD48)
#define runner_b_vlan_command_add_two_tags		(0xDBC)
#define runner_b_vlan_command_add_outer_tag_replace_inner_tag		(0xE48)
#define runner_b_vlan_command_replace_outer_tag		(0xED0)
#define runner_b_vlan_command_replace_two_tags		(0xF2C)
#define runner_b_vlan_command_remove_tag		(0xF78)
#define runner_b_vlan_command_remove_tag_dont_save		(0xFE8)
#define runner_b_vlan_command_remove_two_tags		(0x104C)
#define runner_b_vlan_command_remove_outer_tag_replace_inner_tag		(0x10B8)
#define runner_b_vlan_command_remove_outer_tag_replace_inner_tag_copy		(0x1134)
#define runner_b_vlan_command_remove_outer_tag_copy		(0x11B4)
#define runner_b_vlan_command_replace_outer_tag_replace_inner_tag		(0x1240)
#define runner_b_pbits_command_transparent		(0x1288)
#define runner_b_pbits_command_outer_configured		(0x1298)
#define runner_b_pbits_command_inner_configured		(0x12B4)
#define runner_b_pbits_command_dscp_copy		(0x12D0)
#define runner_b_pbits_command_copy_inner_to_outer		(0x131C)
#define runner_b_pbits_command_increment_offset_copy_inner_to_outer		(0x1344)
#define runner_b_pbits_command_remap		(0x1374)
#define runner_b_pbits_command_decrement_offset_remap		(0x13A4)
#define runner_b_pbits_command_remap_outer_by_inner		(0x13D8)
#define runner_b_pbits_command_configured_two_tags		(0x1418)
#define runner_b_pbits_command_dscp_copy_two_tags		(0x144C)
#define runner_b_global_register_update_r0		(0x3114)
#define runner_b_global_register_update_r1		(0x311C)
#define runner_b_global_register_update_r2		(0x3124)
#define runner_b_global_register_update_r3		(0x312C)
#define runner_b_global_register_update_r4		(0x3134)
#define runner_b_global_register_update_r5		(0x313C)
#define runner_b_global_register_update_r6		(0x3144)
#define runner_b_global_register_update_r7		(0x314C)
#define runner_b_cpu_rx_meter_budget_allocate		(0x3628)
#define runner_b_upstream_rate_limiter_budget_allocate		(0x3674)

#endif
