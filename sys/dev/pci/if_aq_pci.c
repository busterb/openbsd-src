/* $OpenBSD: if_aq_pci.c,v 1.34 2026/01/15 06:41:21 dlg Exp $ */
/*	$NetBSD: if_aq.c,v 1.27 2021/06/16 00:21:18 riastradh Exp $	*/

/*
 * Copyright (c) 2021 Jonathan Matthew <jonathan@d14n.org>
 * Copyright (c) 2021 Mike Larkin <mlarkin@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * aQuantia Corporation Network Driver
 * Copyright (C) 2014-2017 aQuantia Corporation. All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   (1) Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer.
 *
 *   (2) Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 *
 *   (3) The name of the author may not be used to endorse or promote
 *   products derived from this software without specific prior
 *   written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*-
 * Copyright (c) 2020 Ryo Shimizu <ryo@nerv.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Driver for aQuantia/Marvell AQtion Ethernet adapters.
 *
 * Supports two hardware generations:
 *   - Atlantic (AQ1): AQC100/107/108/109/111/112 and variants
 *   - Atlantic2 (AQ2): AQC113/114/115/116 and variants
 *
 * These are multi-gigabit (up to 10Gbps) PCI Express NICs with:
 *   - Multi-queue TX/RX with MSI-X support (up to 8 queues)
 *   - RSS (Receive Side Scaling) via Toeplitz hashing
 *   - Hardware checksum offload (IPv4, TCP, UDP)
 *   - VLAN tag insertion/stripping
 *   - SFP module access via SMBus (fibre variants)
 *
 * The driver communicates with on-chip firmware via memory-mapped
 * registers and a mailbox interface.  AQ1 devices use firmware
 * versions 1.x (fw1x) or 2.x/3.x (fw2x), while AQ2 devices use
 * a separate firmware interface with shared memory regions.
 */

#include "bpfilter.h"	/* BPF (Berkeley Packet Filter) support */
#include "vlan.h"	/* VLAN (802.1Q) support */

#include <sys/types.h>
#include <sys/device.h>	  /* OpenBSD autoconf device framework */
#include <sys/param.h>
#include <sys/sockio.h>	  /* socket ioctl definitions (SIOCSIFADDR, etc.) */
#include <sys/systm.h>	  /* kernel utility functions (delay, printf, etc.) */
#include <sys/intrmap.h>  /* interrupt-to-CPU mapping for multi-queue */

#include <net/if.h>	  /* struct ifnet - network interface abstraction */
#include <net/if_media.h> /* ifmedia - link speed/duplex negotiation */
#include <net/toeplitz.h> /* Toeplitz hash for RSS key generation */

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/if_ether.h>

#ifdef __HAVE_FDT
#include <dev/ofw/openfirm.h>	/* Device Tree support for MAC addr on ARM */
#endif

#include <dev/pci/pcireg.h>	/* PCI register definitions */
#include <dev/pci/pcivar.h>	/* PCI bus access functions */
#include <dev/pci/pcidevs.h>	/* PCI vendor/product ID constants */

#if NBPFILTER > 0
#include <net/bpf.h>		/* BPF tap for tcpdump/packet capture */
#endif

/* #define AQ_DEBUG 1 */
#ifdef AQ_DEBUG
#define DPRINTF(x) printf x
#else
#define DPRINTF(x)
#endif /* AQ_DEBUG */

/* Convenience macro: returns the autoconf device name (e.g. "aq0") */
#define DEVNAME(_s)	((_s)->sc_dev.dv_xname)

/*
 * Basic hardware constants.
 */
#define AQ_BAR0 				0x10	/* PCI BAR for MMIO */
#define AQ_MAXQ 				8	/* max HW queues */
#define AQ_RSS_KEYSIZE				40	/* RSS key: 40 bytes */
#define AQ_RSS_REDIR_ENTRIES			12	/* RSS redir table regs */

#define AQ_TXD_NUM 				2048	/* TX descriptors/ring */
#define AQ_RXD_NUM 				2048	/* RX descriptors/ring */

#define AQ_TX_MAX_SEGMENTS			32	/* max DMA segs per TX */

#define AQ_LINKSTAT_IRQ				31	/* link status IRQ # */

#define RPF_ACTION_HOST				1	/* deliver to host */

/*
 * Global / firmware control registers.
 * These are used during firmware boot, reset, and version identification.
 */
#define AQ_FW_SOFTRESET_REG			0x0000
#define  AQ_FW_SOFTRESET_DIS			(1 << 14)
#define  AQ_FW_SOFTRESET_RESET			(1 << 15)
#define AQ_FW_VERSION_REG			0x0018
#define AQ_HW_REVISION_REG			0x001c
#define AQ2_HW_FPGA_VERSION_REG			0x00f4
#define AQ_GLB_NVR_INTERFACE1_REG		0x0100
#define AQ_FW_MBOX_CMD_REG			0x0200
#define  AQ_FW_MBOX_CMD_EXECUTE			0x00008000
#define  AQ_FW_MBOX_CMD_BUSY			0x00000100
#define AQ_FW_MBOX_ADDR_REG			0x0208
#define AQ_FW_MBOX_VAL_REG			0x020C
#define AQ_FW_GLB_CPU_SEM_REG(i)		(0x03a0 + (i) * 4)
#define AQ_FW_SEM_RAM_REG			AQ_FW_GLB_CPU_SEM_REG(2)
#define AQ2_ART_SEM_REG				AQ_FW_GLB_CPU_SEM_REG(3)
#define AQ_FW_GLB_CTL2_REG			0x0404
#define AQ_GLB_GENERAL_PROVISIONING9_REG	0x0520
#define AQ_GLB_NVR_PROVISIONING2_REG		0x0534
/*
 * Interrupt controller registers.
 * The NIC has a 32-bit interrupt status register with one bit per source.
 * Sources include per-queue TX/RX completion and link status change.
 * The automask register causes hardware to auto-clear interrupt bits
 * on read, avoiding a separate write to acknowledge.
 */
#define AQ_INTR_STATUS_REG			0x2000  /* intr status */
#define AQ_INTR_STATUS_CLR_REG			0x2050  /* intr status clear */
#define AQ_INTR_MASK_REG			0x2060	/* intr mask set */
#define AQ_INTR_MASK_CLR_REG			0x2070	/* intr mask clear */
#define AQ_INTR_AUTOMASK_REG			0x2090

#define AQ_SMB_PROVISIONING_REG			0x0604
#define AQ_SMB_TX_DATA_REG			0x0608
#define AQ_SMB_BUS_REG				0x0744
#define  AQ_SMB_BUS_XFER_COMPLETE		(1 << 1)
#define  AQ_SMB_BUS_REPEAT_DETECT		(1 << 2)
#define  AQ_SMB_BUS_BUSY			(1 << 7)
#define  AQ_SMB_BUS_RX_ACK			(1 << 8)
#define AQ_SMB_RX_DATA_REG			0x0748

/*
 * Interrupt-to-IRQ mapping registers (0x2100-0x2140).
 * These map each TX/RX queue's completion event to a specific MSI-X
 * vector number.  Two queues are packed into each 32-bit register.
 */
#define AQ_INTR_IRQ_MAP_TXRX_REG(i)		(0x2100 + ((i) / 2) * 4)
#define AQ_INTR_IRQ_MAP_TX_REG(i)		AQ_INTR_IRQ_MAP_TXRX_REG(i)
#define  AQ_INTR_IRQ_MAP_TX_IRQMAP(i)		(0x1FU << (((i) & 1) ? 16 : 24))
#define  AQ_INTR_IRQ_MAP_TX_EN(i)		(1U << (((i) & 1) ? 23 : 31))
#define AQ_INTR_IRQ_MAP_RX_REG(i)		AQ_INTR_IRQ_MAP_TXRX_REG(i)
#define  AQ_INTR_IRQ_MAP_RX_IRQMAP(i)		(0x1FU << (((i) & 1) ? 0 : 8))
#define  AQ_INTR_IRQ_MAP_RX_EN(i)		(1U << (((i) & 1) ? 7 : 15))

/* AQ_GEN_INTR_MAP_REG[AQ_RINGS_NUM] 0x2180-0x2200 */
#define AQ_GEN_INTR_MAP_REG(i)			(0x2180 + (i) * 4)
#define  AQ_B0_ERR_INT				8U

#define ITR_RSC_EN_REG				0x2200
#define ITR_RSC_DELAY_REG			0x2204
#define  ITR_RSC_DELAY				0x0000000f

#define AQ_INTR_CTRL_REG			0x2300
#define  AQ_INTR_CTRL_IRQMODE			((1 << 0) | (1 << 1))
#define AQ_INTR_CTRL_IRQMODE_LEGACY		0
#define AQ_INTR_CTRL_IRQMODE_MSI		1
#define AQ_INTR_CTRL_IRQMODE_MSIX		2
#define  AQ_INTR_CTRL_MULTIVEC			(1 << 2)
#define  AQ_INTR_CTRL_RESET_DIS			(1 << 29)
#define  AQ_INTR_CTRL_RESET_IRQ			(1U << 31)
#define AQ_MBOXIF_POWER_GATING_CONTROL_REG	0x32a8

#define FW_MPI_MBOX_ADDR_REG			0x0360
#define FW1X_MPI_INIT1_REG			0x0364
#define FW1X_MPI_INIT2_REG			0x0370
#define FW1X_MPI_EFUSEADDR_REG			0x0374

#define FW2X_MPI_EFUSEADDR_REG			0x0364
#define FW2X_MPI_CONTROL_REG			0x0368  /* 64bit */
#define FW2X_MPI_STATE_REG			0x0370  /* 64bit */
#define FW_BOOT_EXIT_CODE_REG			0x0388

#define FW_BOOT_EXIT_CODE_REG			0x0388
#define  RBL_STATUS_DEAD			0x0000dead
#define  RBL_STATUS_SUCCESS			0x0000abba
#define  RBL_STATUS_FAILURE			0x00000bad
#define  RBL_STATUS_HOST_BOOT			0x0000f1a7
#define FW_MPI_DAISY_CHAIN_STATUS_REG		0x0704
#define AQ_PCI_REG_CONTROL_6_REG		0x1014

#define FW_MPI_RESETCTRL_REG			0x4000
#define  FW_MPI_RESETCTRL_RESET_DIS		(1 << 29)

/*
 * Receive path registers (0x5000-0x6fff).
 * RPF = Receive Packet Filter (L2/L3/L4 filtering, RSS, VLAN)
 * RPB = Receive Packet Buffer (on-chip RX FIFO)
 * RPO = Receive Packet Offload (checksum offload)
 * RX DMA = DMA engine registers for RX descriptor rings
 */
#define RX_SYSCONTROL_REG			0x5000
#define  RX_SYSCONTROL_RESET_DIS		(1 << 29)

#define RX_TCP_RSS_HASH_REG			0x5040
#define  RX_TCP_RSS_HASH_RPF2			(0xf << 16)
#define  RX_TCP_RSS_HASH_TYPE			(0xffff)

#define RPF_L2BC_REG				0x5100
#define  RPF_L2BC_EN				(1 << 0)
#define  RPF_L2BC_PROMISC			(1 << 3)
#define  RPF_L2BC_ACTION			0x7000
#define  RPF_L2BC_THRESHOLD			0xFFFF0000

#define AQ_HW_MAC_OWN				0

/* RPF_L2UC_*_REG[34] (actual [38]?) */
#define RPF_L2UC_LSW_REG(i)                     (0x5110 + (i) * 8)
#define RPF_L2UC_MSW_REG(i)                     (0x5114 + (i) * 8)
#define  RPF_L2UC_MSW_MACADDR_HI		0xFFFF
#define  RPF_L2UC_MSW_ACTION			0x70000
#define  RPF_L2UC_MSW_TAG			0x03c00000
#define  RPF_L2UC_MSW_EN			(1U << 31)
#define AQ_HW_MAC_NUM				34

/* RPF_MCAST_FILTER_REG[8] 0x5250-0x5270 */
#define RPF_MCAST_FILTER_REG(i)			(0x5250 + (i) * 4)
#define  RPF_MCAST_FILTER_EN			(1U << 31)
#define RPF_MCAST_FILTER_MASK_REG		0x5270
#define  RPF_MCAST_FILTER_MASK_ALLMULTI		(1 << 14)

#define RPF_VLAN_MODE_REG			0x5280
#define  RPF_VLAN_MODE_PROMISC			(1 << 1)
#define  RPF_VLAN_MODE_ACCEPT_UNTAGGED		(1 << 2)
#define  RPF_VLAN_MODE_UNTAGGED_ACTION		0x38

#define RPF_VLAN_TPID_REG                       0x5284
#define  RPF_VLAN_TPID_OUTER			0xFFFF0000
#define  RPF_VLAN_TPID_INNER			0xFFFF

/* RPF_ETHERTYPE_FILTER_REG[AQ_RINGS_NUM] 0x5300-0x5380 */
#define RPF_ETHERTYPE_FILTER_REG(i)		(0x5300 + (i) * 4)
#define  RPF_ETHERTYPE_FILTER_EN		(1U << 31)

/* RPF_L3_FILTER_REG[8] 0x5380-0x53a0 */
#define RPF_L3_FILTER_REG(i)			(0x5380 + (i) * 4)
#define  RPF_L3_FILTER_L4_EN			(1U << 31)

#define RX_FLR_RSS_CONTROL1_REG			0x54c0
#define  RX_FLR_RSS_CONTROL1_EN			(1U << 31)

#define RPF_RPB_RX_TC_UPT_REG                   0x54c4
#define  RPF_RPB_RX_TC_UPT_MASK(i)              (0x00000007 << ((i) * 4))

#define RPF_RSS_KEY_ADDR_REG			0x54d0
#define  RPF_RSS_KEY_ADDR			0x1f
#define  RPF_RSS_KEY_WR_EN			(1 << 5)
#define RPF_RSS_KEY_WR_DATA_REG			0x54d4
#define RPF_RSS_KEY_RD_DATA_REG			0x54d8

#define RPF_RSS_REDIR_ADDR_REG			0x54e0
#define  RPF_RSS_REDIR_ADDR			0xf
#define  RPF_RSS_REDIR_WR_EN			(1 << 4)

#define RPF_RSS_REDIR_WR_DATA_REG		0x54e4


#define RPO_HWCSUM_REG				0x5580
#define  RPO_HWCSUM_L4CSUM_EN			(1 << 0)
#define  RPO_HWCSUM_IP4CSUM_EN			(1 << 1)

#define RPO_LRO_EN_REG				0x5590
#define RPO_LRO_CONF_REG			0x5594
#define  RPO_LRO_CONF_PKT_MIN			0x0000001f
#define  RPO_LRO_CONF_TOT_DSC_LMT		0x00000060
#define  RPO_LRO_CONF_QSES_LMT			0x00003000
#define  RPO_LRO_CONF_PTOPT_EN			0x00008000
#define RPO_LRO_RSC_MAX_REG			0x5598

/* RPO_LRO_DESC_MAX_REG: 4 regs, 8 rings each, 4 bits/ring (2-bit value) */
#define RPO_LRO_DESC_MAX_REG(i)		(0x55a0 + ((i) / 8) * 4)
#define  RPO_LRO_DESC_MAX_MASK(i)		(0x3U << (((i) % 8) * 4))

#define RPO_LRO_TIMER_REG			0x5620
#define  RPO_LRO_TIMER_MAX_IVAL			0x000003ff
#define  RPO_LRO_TIMER_INA_IVAL			0x000ffc00
#define  RPO_LRO_TIMER_TB_DIV			0xfff00000

#define RPB_RPF_RX_REG				0x5700
#define  RPB_RPF_RX_TC_MODE			(1 << 8)
#define  RPB_RPF_RX_FC_MODE			0x30
#define  RPB_RPF_RX_BUF_EN			(1 << 0)

/* RPB_RXB_BUFSIZE_REG[AQ_TRAFFICCLASS_NUM] 0x5710-0x5790 */
#define RPB_RXB_BUFSIZE_REG(i)			(0x5710 + (i) * 0x10)
#define  RPB_RXB_BUFSIZE			0x1FF
#define RPB_RXB_XOFF_REG(i)			(0x5714 + (i) * 0x10)
#define  RPB_RXB_XOFF_EN			(1U << 31)
#define  RPB_RXB_XOFF_THRESH_HI                 0x3FFF0000
#define  RPB_RXB_XOFF_THRESH_LO                 0x3FFF

#define RX_DMA_DESC_CACHE_INIT_REG		0x5a00
#define  RX_DMA_DESC_CACHE_INIT			(1 << 0)

#define RX_DMA_INT_DESC_WRWB_EN_REG		0x5a30
#define  RX_DMA_INT_DESC_WRWB_EN		(1 << 2)
#define  RX_DMA_INT_DESC_MODERATE_EN		(1 << 3)

#define RX_INTR_MODERATION_CTL_REG(i)		(0x5a40 + (i) * 4)
#define  RX_INTR_MODERATION_CTL_EN		(1 << 1)
#define  RX_INTR_MODERATION_CTL_MIN		(0xFF << 8)
#define  RX_INTR_MODERATION_CTL_MAX		(0x1FF << 16)

#define RX_DMA_DESC_BASE_ADDRLSW_REG(i)		(0x5b00 + (i) * 0x20)
#define RX_DMA_DESC_BASE_ADDRMSW_REG(i)		(0x5b04 + (i) * 0x20)
#define RX_DMA_DESC_REG(i)			(0x5b08 + (i) * 0x20)
#define  RX_DMA_DESC_LEN			(0x3FF << 3)
#define  RX_DMA_DESC_RESET			(1 << 25)
#define  RX_DMA_DESC_HEADER_SPLIT		(1 << 28)
#define  RX_DMA_DESC_VLAN_STRIP			(1 << 29)
#define  RX_DMA_DESC_EN				(1U << 31)
#define RX_DMA_DESC_HEAD_PTR_REG(i)		(0x5b0c + (i) * 0x20)
#define  RX_DMA_DESC_HEAD_PTR			0xFFF
#define RX_DMA_DESC_TAIL_PTR_REG(i)		(0x5b10 + (i) * 0x20)
#define RX_DMA_DESC_BUFSIZE_REG(i)		(0x5b18 + (i) * 0x20)
#define  RX_DMA_DESC_BUFSIZE_DATA		0x000F
#define  RX_DMA_DESC_BUFSIZE_HDR		0x0FF0

#define RX_DMA_DCAD_REG(i)			(0x6100 + (i) * 4)
#define  RX_DMA_DCAD_CPUID			0xFF
#define  RX_DMA_DCAD_PAYLOAD_EN			(1 << 29)
#define  RX_DMA_DCAD_HEADER_EN			(1 << 30)
#define  RX_DMA_DCAD_DESC_EN			(1U << 31)

#define RX_DMA_DCA_REG				0x6180
#define  RX_DMA_DCA_EN				(1U << 31)
#define  RX_DMA_DCA_MODE			0xF

/*
 * Transmit path registers (0x7000-0x8fff).
 * TPS = TX Packet Scheduler (arbitration, rate limiting, traffic classes)
 * TPO = TX Packet Offload (checksum, LSO/TSO)
 * TPB = TX Packet Buffer (on-chip TX FIFO)
 * THM = TX Header Modification (LSO TCP flags)
 * TX DMA = DMA engine registers for TX descriptor rings
 * TDM = TX DMA (DCA = Direct Cache Access hints)
 */
#define TX_SYSCONTROL_REG			0x7000
#define  TX_SYSCONTROL_RESET_DIS		(1 << 29)

#define TX_TPO2_REG				0x7040
#define  TX_TPO2_EN				(1 << 16)

#define TPS_DESC_VM_ARB_MODE_REG		0x7300
#define  TPS_DESC_VM_ARB_MODE			(1 << 0)
#define TPS_DESC_RATE_REG			0x7310
#define  TPS_DESC_RATE_TA_RST			(1U << 31)
#define  TPS_DESC_RATE_LIM			0x7FF
#define TPS_DESC_TC_ARB_MODE_REG		0x7200
#define  TPS_DESC_TC_ARB_MODE			0x3
#define TPS_DATA_TC_ARB_MODE_REG		0x7100
#define  TPS_DATA_TC_ARB_MODE			(1 << 0)

/* TPS_DATA_TCT_REG[AQ_TRAFFICCLASS_NUM] 0x7110-0x7130 */
#define TPS_DATA_TCT_REG(i)			(0x7110 + (i) * 4)
#define  TPS_DATA_TCT_CREDIT_MAX		0xFFF0000
#define  TPS_DATA_TCT_WEIGHT			0x1FF
#define  TPS2_DATA_TCT_CREDIT_MAX		0xFFFF0000
#define  TPS2_DATA_TCT_WEIGHT			0x7FFF
/* TPS_DATA_TCT_REG[AQ_TRAFFICCLASS_NUM] 0x7210-0x7230 */
#define TPS_DESC_TCT_REG(i)			(0x7210 + (i) * 4)
#define  TPS_DESC_TCT_CREDIT_MAX		0xFFF0000
#define  TPS_DESC_TCT_WEIGHT			0x1FF

#define AQ_HW_TXBUF_MAX         160
#define AQ_HW_RXBUF_MAX         320
#define AQ2_HW_TXBUF_MAX	128
#define AQ2_HW_RXBUF_MAX	192

#define TPO_HWCSUM_REG				0x7800
#define  TPO_HWCSUM_L4CSUM_EN			(1 << 0)
#define  TPO_HWCSUM_IP4CSUM_EN			(1 << 1)

#define TDM_LSO_ENABLE					0x7810

#define THM_LSO_TCP_FLAG1_REG			0x7820
#define  THM_LSO_TCP_FLAG1_FIRST		0xFFF
#define  THM_LSO_TCP_FLAG1_MID			0xFFF0000
#define THM_LSO_TCP_FLAG2_REG			0x7824
#define  THM_LSO_TCP_FLAG2_LAST			0xFFF

#define TPB_TX_BUF_REG				0x7900
#define  TPB_TX_BUF_EN				(1 << 0)
#define  TPB_TX_BUF_SCP_INS_EN			(1 << 2)
#define  TPB_TX_BUF_CLK_GATE_EN			(1 << 5)
#define  TPB_TX_BUF_TC_MODE_EN			(1 << 8)
#define  TPB_TX_BUF_TC_Q_RAND_MAP_EN		(1 << 9)


/* TPB_TXB_BUFSIZE_REG[AQ_TRAFFICCLASS_NUM] 0x7910-7990 */
#define TPB_TXB_BUFSIZE_REG(i)			(0x7910 + (i) * 0x10)
#define  TPB_TXB_BUFSIZE                        (0xFF)
#define TPB_TXB_THRESH_REG(i)                   (0x7914 + (i) * 0x10)
#define  TPB_TXB_THRESH_HI                      0x1FFF0000
#define  TPB_TXB_THRESH_LO                      0x1FFF

#define AQ_HW_TX_DMA_TOTAL_REQ_LIMIT_REG	0x7b20

#define TX_DMA_INT_DESC_WRWB_EN_REG		0x7b40
#define  TX_DMA_INT_DESC_WRWB_EN		(1 << 1)
#define  TX_DMA_INT_DESC_MODERATE_EN		(1 << 4)

#define TX_DMA_DESC_BASE_ADDRLSW_REG(i)		(0x7c00 + (i) * 0x40)
#define TX_DMA_DESC_BASE_ADDRMSW_REG(i)		(0x7c04 + (i) * 0x40)
#define TX_DMA_DESC_REG(i)			(0x7c08 + (i) * 0x40)
#define  TX_DMA_DESC_LEN			0x00000FF8
#define  TX_DMA_DESC_EN				0x80000000
#define TX_DMA_DESC_HEAD_PTR_REG(i)		(0x7c0c + (i) * 0x40)
#define  TX_DMA_DESC_HEAD_PTR			0x00000FFF
#define TX_DMA_DESC_TAIL_PTR_REG(i)		(0x7c10 + (i) * 0x40)
#define TX_DMA_DESC_WRWB_THRESH_REG(i)		(0x7c18 + (i) * 0x40)
#define  TX_DMA_DESC_WRWB_THRESH		0x00003F00

#define TDM_DCAD_REG(i)				(0x8400 + (i) * 4)
#define  TDM_DCAD_CPUID				0x7F
#define  TDM_DCAD_CPUID_EN			0x80000000

#define TDM_DCA_REG				0x8480
#define  TDM_DCA_EN				(1U << 31)
#define  TDM_DCA_MODE				0xF

#define TX_INTR_MODERATION_CTL_REG(i)		(0x8980 + (i) * 4)
#define  TX_INTR_MODERATION_CTL_EN		(1 << 1)
#define  TX_INTR_MODERATION_CTL_MIN		(0xFF << 8)
#define  TX_INTR_MODERATION_CTL_MAX		(0x1FF << 16)

/*
 * Atlantic2 (AQ2) specific registers.
 * AQ2 uses a different firmware interface based on shared memory regions
 * at high register offsets (0x12000+, 0x13000+, 0x14000+).  The driver
 * writes configuration to the "interface in" region and reads status
 * from the "interface out" region, using transaction IDs for coherency.
 */

#define AQ2_MIF_HOST_FINISHED_STATUS_WRITE_REG	0x0e00
#define AQ2_MIF_HOST_FINISHED_STATUS_READ_REG	0x0e04
#define  AQ2_MIF_HOST_FINISHED_STATUS_ACK	(1 << 0)

#define AQ2_MCP_HOST_REQ_INT_REG		0x0f00
#define  AQ2_MCP_HOST_REQ_INT_READY		(1 << 0)
#define AQ2_MCP_HOST_REQ_INT_SET_REG		0x0f04
#define AQ2_MCP_HOST_REQ_INT_CLR_REG		0x0f08

#define AQ2_MIF_BOOT_REG			0x3040
#define  AQ2_MIF_BOOT_HOST_DATA_LOADED		(1 << 16)
#define  AQ2_MIF_BOOT_BOOT_STARTED		(1 << 24)
#define  AQ2_MIF_BOOT_CRASH_INIT		(1 << 27)
#define  AQ2_MIF_BOOT_BOOT_CODE_FAILED		(1 << 28)
#define  AQ2_MIF_BOOT_FW_INIT_FAILED		(1 << 29)
#define  AQ2_MIF_BOOT_FW_INIT_COMP_SUCCESS	(1U << 31)

/*
 * AQ2 Action Resolver Table (ART).
 * The ART is a programmable packet classification engine in AQ2 hardware.
 * Each entry has a tag (match value), mask, and action.  Packets are
 * matched against the table to determine whether to drop, forward to
 * host, or assign to a specific queue/traffic class.
 */
#define AQ2_ART_ACTION_ACT_SHIFT		8
#define AQ2_ART_ACTION_RSS			0x0080
#define AQ2_ART_ACTION_INDEX_SHIFT		2
#define AQ2_ART_ACTION_ENABLE			0x0001
#define AQ2_ART_ACTION(act, rss, idx, en)		\
	(((act) << AQ2_ART_ACTION_ACT_SHIFT) |		\
	((rss) ? AQ2_ART_ACTION_RSS : 0) |		\
	((idx) << AQ2_ART_ACTION_INDEX_SHIFT) |		\
	((en) ? AQ2_ART_ACTION_ENABLE : 0))
#define AQ2_ART_ACTION_DROP			AQ2_ART_ACTION(0, 0, 0, 1)
#define AQ2_ART_ACTION_DISABLE			AQ2_ART_ACTION(0, 0, 0, 0)
#define AQ2_ART_ACTION_ASSIGN_QUEUE(q)		AQ2_ART_ACTION(1, 0, (q), 1)
#define AQ2_ART_ACTION_ASSIGN_TC(tc)		AQ2_ART_ACTION(1, 1, (tc), 1)

#define AQ2_RPF_TAG_PCP_MASK			0xe0000000
#define AQ2_RPF_TAG_PCP_SHIFT			29
#define AQ2_RPF_TAG_FLEX_MASK			0x18000000
#define AQ2_RPF_TAG_UNKNOWN_MASK		0x07000000
#define AQ2_RPF_TAG_L4_MASK			0x00e00000
#define AQ2_RPF_TAG_L3_V6_MASK			0x001c0000
#define AQ2_RPF_TAG_L3_V4_MASK			0x00038000
#define AQ2_RPF_TAG_UNTAG_MASK			0x00004000
#define AQ2_RPF_TAG_VLAN_MASK			0x00003c00
#define AQ2_RPF_TAG_ET_MASK			0x00000380
#define AQ2_RPF_TAG_ALLMC_MASK			0x00000040
#define AQ2_RPF_TAG_UC_MASK			0x0000002f

/* index of aq2_filter_art_set() */
#define AQ2_RPF_INDEX_L2_PROMISC_OFF		0
#define AQ2_RPF_INDEX_VLAN_PROMISC_OFF		1
#define AQ2_RPF_INDEX_L3L4_USER			8
#define AQ2_RPF_INDEX_ET_PCP_USER		24
#define AQ2_RPF_INDEX_VLAN_USER			40
#define AQ2_RPF_INDEX_PCP_TO_TC			56

#define AQ2_RPF_L2BC_TAG_REG			0x50f0
#define  AQ2_RPF_L2BC_TAG_MASK			0x0000003f

#define AQ2_RPF_NEW_CTRL_REG			0x5104
#define  AQ2_RPF_NEW_CTRL_ENABLE		(1 << 11)

#define AQ2_RPF_REDIR2_REG			0x54c8
#define  AQ2_RPF_REDIR2_INDEX			(1 << 12)
#define  AQ2_RPF_REDIR2_HASHTYPE		0x000001FF
#define  AQ2_RPF_REDIR2_HASHTYPE_NONE		0
#define  AQ2_RPF_REDIR2_HASHTYPE_IP		(1 << 0)
#define  AQ2_RPF_REDIR2_HASHTYPE_TCP4		(1 << 1)
#define  AQ2_RPF_REDIR2_HASHTYPE_UDP4		(1 << 2)
#define  AQ2_RPF_REDIR2_HASHTYPE_IP6		(1 << 3)
#define  AQ2_RPF_REDIR2_HASHTYPE_TCP6		(1 << 4)
#define  AQ2_RPF_REDIR2_HASHTYPE_UDP6		(1 << 5)
#define  AQ2_RPF_REDIR2_HASHTYPE_IP6EX		(1 << 6)
#define  AQ2_RPF_REDIR2_HASHTYPE_TCP6EX		(1 << 7)
#define  AQ2_RPF_REDIR2_HASHTYPE_UDP6EX		(1 << 8)
#define  AQ2_RPF_REDIR2_HASHTYPE_ALL		0x000001FF

#define AQ2_RX_Q_TC_MAP_REG(i)			(0x5900 + (i) * 4)
#define AQ2_TX_Q_TC_MAP_REG(i)			(0x799c + (i) * 4)

#define AQ2_RPF_RSS_REDIR_MAX			64
#define AQ2_RPF_RSS_REDIR_REG(tc, i)		\
	 (0x6200 + (0x100 * ((tc) >> 2)) + (i) * 4)
#define AQ2_RPF_RSS_REDIR_TC_MASK(tc)		\
	 (0x1f << (5 * ((tc) & 3)))

#define AQ2_RPF_REC_TAB_ENABLE_REG		0x6ff0
#define  AQ2_RPF_REC_TAB_ENABLE_MASK		0x0000ffff

#define AQ2_LAUNCHTIME_CTRL_REG			0x7a1c
#define  AQ2_LAUNCHTIME_CTRL_RATIO		0x0000ff00
#define  AQ2_LAUNCHTIME_CTRL_RATIO_SPEED_QUARTER 4
#define  AQ2_LAUNCHTIME_CTRL_RATIO_SPEED_HALF	2
#define  AQ2_LAUNCHTIME_CTRL_RATIO_SPEED_FULL	1

#define AQ2_TX_INTR_MODERATION_CTL_REG(i)	(0x7c28 + (i) * 0x40)
#define  AQ2_TX_INTR_MODERATION_CTL_EN		(1 << 1)
#define  AQ2_TX_INTR_MODERATION_CTL_MIN		0x0000ff00
#define  AQ2_TX_INTR_MODERATION_CTL_MAX		0x01ff0000

#define AQ2_FW_INTERFACE_IN_MTU_REG		0x12000
#define AQ2_FW_INTERFACE_IN_MAC_ADDRESS_REG	0x12008

#define AQ2_FW_INTERFACE_IN_LINK_CONTROL_REG	0x12010
#define  AQ2_FW_INTERFACE_IN_LINK_CONTROL_MODE	0x0000000f
#define  AQ2_FW_INTERFACE_IN_LINK_CONTROL_MODE_INVALID	0
#define  AQ2_FW_INTERFACE_IN_LINK_CONTROL_MODE_ACTIVE	1
#define  AQ2_FW_INTERFACE_IN_LINK_CONTROL_MODE_SLEEP_PROXY 2
#define  AQ2_FW_INTERFACE_IN_LINK_CONTROL_MODE_LOWPOWER	3
#define  AQ2_FW_INTERFACE_IN_LINK_CONTROL_MODE_SHUTDOWN	4

#define AQ2_FW_INTERFACE_IN_LINK_OPTIONS_REG	0x12018
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_DOWNSHIFT	(1 << 27)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_PAUSE_TX	(1 << 25)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_PAUSE_RX	(1 << 24)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_10G	(1 << 20)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_5G	(1 << 19)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_2G5	(1 << 18)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_1G	(1 << 17)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EEE_100M	(1 << 16)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_10G	(1 << 15)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_N5G	(1 << 14)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_5G	(1 << 13)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_N2G5	(1 << 12)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_2G5	(1 << 11)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_1G	(1 << 10)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_100M	(1 << 9)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_10M	(1 << 8)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_1G_HD	(1 << 7)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_100M_HD	(1 << 6)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_10M_HD	(1 << 5)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_EXTERNAL_LOOPBACK (1 << 4)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_INTERNAL_LOOPBACK (1 << 3)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_MINIMAL_LINK_SPEED (1 << 2)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_LINK_RENEGOTIATE (1 << 1)
#define  AQ2_FW_INTERFACE_IN_LINK_OPTIONS_LINK_UP	(1 << 0)

#define AQ2_FW_INTERFACE_IN_REQUEST_POLICY_REG	0x12a58
#define  AQ2_FW_INTERFACE_IN_REQUEST_POLICY_MCAST_QUEUE_OR_TC		0x00800000
#define  AQ2_FW_INTERFACE_IN_REQUEST_POLICY_MCAST_RX_QUEUE_TC_INDEX	0x007c0000
#define  AQ2_FW_INTERFACE_IN_REQUEST_POLICY_MCAST_ACCEPT		0x00010000
#define  AQ2_FW_INTERFACE_IN_REQUEST_POLICY_BCAST_QUEUE_OR_TC		0x00008000
#define  AQ2_FW_INTERFACE_IN_REQUEST_POLICY_BCAST_RX_QUEUE_TC_INDEX	0x00007c00
#define  AQ2_FW_INTERFACE_IN_REQUEST_POLICY_BCAST_ACCEPT		0x00000100
#define  AQ2_FW_INTERFACE_IN_REQUEST_POLICY_PROMISC_QUEUE_OR_TC		0x00000080
#define  AQ2_FW_INTERFACE_IN_REQUEST_POLICY_PROMISC_RX_QUEUE_TX_INDEX	0x0000007c
#define  AQ2_FW_INTERFACE_IN_REQUEST_POLICY_PROMISC_MCAST		0x00000002
#define  AQ2_FW_INTERFACE_IN_REQUEST_POLICY_PROMISC_ALL			0x00000001

#define AQ2_FW_INTERFACE_OUT_TRANSACTION_ID_REG	0x13000
#define  AQ2_FW_INTERFACE_OUT_TRANSACTION_ID_B	0xffff0000
#define  AQ2_FW_INTERFACE_OUT_TRANSACTION_ID_B_S 16
#define  AQ2_FW_INTERFACE_OUT_TRANSACTION_ID_A	0x0000ffff
#define  AQ2_FW_INTERFACE_OUT_TRANSACTION_ID_A_S 0

#define AQ2_FW_INTERFACE_OUT_VERSION_BUNDLE_REG	0x13004
#define AQ2_FW_INTERFACE_OUT_VERSION_MAC_REG	0x13008

#define AQ2_FW_INTERFACE_OUT_VERSION_PHY_REG	0x1300c
#define  AQ2_FW_INTERFACE_OUT_VERSION_BUILD	0xffff0000
#define  AQ2_FW_INTERFACE_OUT_VERSION_BUILD_S	16
#define  AQ2_FW_INTERFACE_OUT_VERSION_MINOR	0x0000ff00
#define  AQ2_FW_INTERFACE_OUT_VERSION_MINOR_S	8
#define  AQ2_FW_INTERFACE_OUT_VERSION_MAJOR	0x000000ff
#define  AQ2_FW_INTERFACE_OUT_VERSION_MAJOR_S	0

#define AQ2_FW_INTERFACE_OUT_VERSION_IFACE_REG	0x13010
#define  AQ2_FW_INTERFACE_OUT_VERSION_IFACE_VER	0x0000000f
#define  AQ2_FW_INTERFACE_OUT_VERSION_IFACE_VER_A0 0
#define  AQ2_FW_INTERFACE_OUT_VERSION_IFACE_VER_B0 1

#define AQ2_FW_INTERFACE_OUT_LINK_STATUS_REG	0x13014
#define  AQ2_FW_INTERFACE_OUT_LINK_STATUS_DUPLEX	(1 << 11)
#define  AQ2_FW_INTERFACE_OUT_LINK_STATUS_EEE		(1 << 10)
#define  AQ2_FW_INTERFACE_OUT_LINK_STATUS_PAUSE_RX	(1 << 9)
#define  AQ2_FW_INTERFACE_OUT_LINK_STATUS_PAUSE_TX	(1 << 8)
#define  AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE		0x000000f0
#define  AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE_S	4
#define  AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE_10G	6
#define  AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE_5G	5
#define  AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE_2G5	4
#define  AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE_1G	3
#define  AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE_100M	2
#define  AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE_10M	1
#define  AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE_INVALID	0
#define  AQ2_FW_INTERFACE_OUT_LINK_STATUS_STATE		0x0000000f

#define AQ2_FW_INTERFACE_OUT_FILTER_CAPS_REG	0x13774
#define  AQ2_FW_INTERFACE_OUT_FILTER_CAPS3_RESOLVER_BASE_INDEX 0x00ff0000
#define  AQ2_FW_INTERFACE_OUT_FILTER_CAPS3_RESOLVER_BASE_INDEX_SHIFT 16

#define AQ2_RPF_ACT_ART_REQ_TAG_REG(i)		(0x14000 + (i) * 0x10)
#define AQ2_RPF_ACT_ART_REQ_MASK_REG(i)		(0x14004 + (i) * 0x10)
#define AQ2_RPF_ACT_ART_REQ_ACTION_REG(i)	(0x14008 + (i) * 0x10)

/*
 * Bit manipulation helpers used for read-modify-write of register fields.
 * __LOWEST_SET_BIT isolates the LSB of a bitmask, and __SHIFTIN shifts
 * a value into the position defined by that mask.
 */
#define __LOWEST_SET_BIT(__mask) (((((uint32_t)__mask) - 1) & ((uint32_t)__mask)) ^ ((uint32_t)__mask))
#define __SHIFTIN(__x, __mask) ((__x) * __LOWEST_SET_BIT(__mask))

/*
 * Register access macros.  All hardware registers are accessed through
 * the bus_space(9) API, which provides MI (machine-independent) access
 * to MMIO space mapped at attach time.
 */
#define AQ_READ_REG(sc, reg) \
	bus_space_read_4((sc)->sc_iot, (sc)->sc_ioh, (reg))
#define AQ_READ_REGS(sc, reg, p, cnt) \
	bus_space_read_region_4((sc)->sc_iot, (sc)->sc_ioh, (reg), (p), (cnt));

#define AQ_WRITE_REG(sc, reg, val) \
	bus_space_write_4((sc)->sc_iot, (sc)->sc_ioh, (reg), (val))

/*
 * Read-modify-write a bitfield within a register.
 * Reads the register, clears the bits in 'mask', then sets them to
 * 'val' shifted into position.  Used extensively for register fields.
 */
#define AQ_WRITE_REG_BIT(sc, reg, mask, val)                    \
	do {                                                    \
		uint32_t _v;                                    \
		_v = AQ_READ_REG((sc), (reg));                  \
		_v &= ~(mask);                                  \
		if ((val) != 0)                                 \
			_v |= __SHIFTIN((val), (mask));         \
		AQ_WRITE_REG((sc), (reg), _v);                  \
	} while (/* CONSTCOND */ 0)

/* 64-bit register access (two consecutive 32-bit reads/writes) */
#define AQ_READ64_REG(sc, reg)					\
	((uint64_t)AQ_READ_REG(sc, reg) |			\
	(((uint64_t)AQ_READ_REG(sc, (reg) + 4)) << 32))

#define AQ_WRITE64_REG(sc, reg, val)				\
	do {							\
		AQ_WRITE_REG(sc, reg, (uint32_t)val);		\
		AQ_WRITE_REG(sc, reg + 4, (uint32_t)(val >> 32)); \
	} while (/* CONSTCOND */0)

/*
 * Poll for a condition with timeout.  Checks 'expr' up to 'n' times,
 * sleeping 'us' microseconds between checks.  Sets *errp to ETIMEDOUT
 * on failure or 0 on success.
 */
#define WAIT_FOR(expr, us, n, errp)                             \
	do {                                                    \
		unsigned int _n;                                \
		for (_n = n; (!(expr)) && _n != 0; --_n) {      \
			delay((us));                            \
		}                                               \
		if ((errp != NULL)) {                           \
			if (_n == 0)                            \
				*(errp) = ETIMEDOUT;            \
			else                                    \
				*(errp) = 0;                    \
		}                                               \
	} while (/* CONSTCOND */ 0)

#define FW_VERSION_MAJOR(sc)	(((sc)->sc_fw_version >> 24) & 0xff)
#define FW_VERSION_MINOR(sc)	(((sc)->sc_fw_version >> 16) & 0xff)
#define FW_VERSION_BUILD(sc)	((sc)->sc_fw_version & 0xffff)

/*
 * Hardware feature/revision flags.
 * Detected at attach time and stored in sc_features.  Used throughout
 * the driver to select codepaths for different chip revisions.
 * MIPS/TPO2/RPF2 indicate specific hardware blocks present.
 */
#define FEATURES_MIPS		0x00000001	/* has MIPS coprocessor */
#define FEATURES_TPO2		0x00000002	/* TX path offload v2 */
#define FEATURES_RPF2		0x00000004	/* RX packet filter v2 */
#define FEATURES_MPI_AQ		0x00000008	/* MPI mailbox available */
#define FEATURES_AQ1_REV_A0	0x01000000	/* Atlantic rev A0 */
#define FEATURES_AQ1_REV_A	(FEATURES_AQ1_REV_A0)
#define FEATURES_AQ1_REV_B0	0x02000000	/* Atlantic rev B0 */
#define FEATURES_AQ1_REV_B1	0x04000000	/* Atlantic rev B1 */
#define FEATURES_AQ1_REV_B	(FEATURES_AQ1_REV_B0|FEATURES_AQ1_REV_B1)
#define FEATURES_AQ1		(FEATURES_AQ1_REV_A|FEATURES_AQ1_REV_B)
#define FEATURES_AQ2		0x10000000	/* Atlantic2 chip */
#define FEATURES_AQ2_IFACE_A0	0x20000000	/* AQ2 FW iface ver A0 */
#define FEATURES_AQ2_IFACE_B0	0x40000000	/* AQ2 FW iface ver B0 */
#define HWTYPE_AQ1_P(sc)	(((sc)->sc_features & FEATURES_AQ1) != 0)
#define HWTYPE_AQ2_P(sc)	(((sc)->sc_features & FEATURES_AQ2) != 0)

/*
 * Mutex protecting the firmware mailbox interface (MPI).
 * Firmware communication is not reentrant, so all accesses to the
 * MPI control/state registers must be serialized.
 */
#define AQ_MPI_LOCK(sc)		mtx_enter(&(sc)->sc_mpi_mutex);
#define AQ_MPI_UNLOCK(sc)	mtx_leave(&(sc)->sc_mpi_mutex);

/*
 * FW2X MPI control register bit definitions.
 * These are written to FW2X_MPI_CONTROL_REG to configure the desired
 * link speeds, EEE modes, and flow control.  The firmware reads this
 * register and negotiates accordingly.  The state register
 * (FW2X_MPI_STATE_REG) uses the same bit layout to report the result.
 */
#define FW2X_CTRL_10BASET_HD			(1 << 0)
#define FW2X_CTRL_10BASET_FD			(1 << 1)
#define FW2X_CTRL_100BASETX_HD			(1 << 2)
#define FW2X_CTRL_100BASET4_HD			(1 << 3)
#define FW2X_CTRL_100BASET2_HD			(1 << 4)
#define FW2X_CTRL_100BASETX_FD			(1 << 5)
#define FW2X_CTRL_100BASET2_FD			(1 << 6)
#define FW2X_CTRL_1000BASET_HD			(1 << 7)
#define FW2X_CTRL_1000BASET_FD			(1 << 8)
#define FW2X_CTRL_2P5GBASET_FD			(1 << 9)
#define FW2X_CTRL_5GBASET_FD			(1 << 10)
#define FW2X_CTRL_10GBASET_FD			(1 << 11)
#define FW2X_CTRL_RESERVED1			(1ULL << 32)
#define FW2X_CTRL_10BASET_EEE			(1ULL << 33)
#define FW2X_CTRL_RESERVED2			(1ULL << 34)
#define FW2X_CTRL_PAUSE				(1ULL << 35)
#define FW2X_CTRL_ASYMMETRIC_PAUSE		(1ULL << 36)
#define FW2X_CTRL_100BASETX_EEE			(1ULL << 37)
#define FW2X_CTRL_RESERVED3			(1ULL << 38)
#define FW2X_CTRL_RESERVED4			(1ULL << 39)
#define FW2X_CTRL_1000BASET_FD_EEE		(1ULL << 40)
#define FW2X_CTRL_2P5GBASET_FD_EEE		(1ULL << 41)
#define FW2X_CTRL_5GBASET_FD_EEE		(1ULL << 42)
#define FW2X_CTRL_10GBASET_FD_EEE		(1ULL << 43)
#define FW2X_CTRL_RESERVED5			(1ULL << 44)
#define FW2X_CTRL_RESERVED6			(1ULL << 45)
#define FW2X_CTRL_RESERVED7			(1ULL << 46)
#define FW2X_CTRL_RESERVED8			(1ULL << 47)
#define FW2X_CTRL_RESERVED9			(1ULL << 48)
#define FW2X_CTRL_CABLE_DIAG			(1ULL << 49)
#define FW2X_CTRL_TEMPERATURE			(1ULL << 50)
#define FW2X_CTRL_DOWNSHIFT			(1ULL << 51)
#define FW2X_CTRL_PTP_AVB_EN			(1ULL << 52)
#define FW2X_CTRL_MEDIA_DETECT			(1ULL << 53)
#define FW2X_CTRL_LINK_DROP			(1ULL << 54)
#define FW2X_CTRL_SLEEP_PROXY			(1ULL << 55)
#define FW2X_CTRL_WOL				(1ULL << 56)
#define FW2X_CTRL_MAC_STOP			(1ULL << 57)
#define FW2X_CTRL_EXT_LOOPBACK			(1ULL << 58)
#define FW2X_CTRL_INT_LOOPBACK			(1ULL << 59)
#define FW2X_CTRL_EFUSE_AGENT			(1ULL << 60)
#define FW2X_CTRL_WOL_TIMER			(1ULL << 61)
#define FW2X_CTRL_STATISTICS			(1ULL << 62)
#define FW2X_CTRL_TRANSACTION_ID		(1ULL << 63)

#define FW2X_CTRL_RATE_100M			FW2X_CTRL_100BASETX_FD
#define FW2X_CTRL_RATE_1G			FW2X_CTRL_1000BASET_FD
#define FW2X_CTRL_RATE_2G5			FW2X_CTRL_2P5GBASET_FD
#define FW2X_CTRL_RATE_5G			FW2X_CTRL_5GBASET_FD
#define FW2X_CTRL_RATE_10G			FW2X_CTRL_10GBASET_FD
#define FW2X_CTRL_RATE_MASK		\
	(FW2X_CTRL_RATE_100M |		\
	 FW2X_CTRL_RATE_1G |		\
	 FW2X_CTRL_RATE_2G5 |		\
	 FW2X_CTRL_RATE_5G |		\
	 FW2X_CTRL_RATE_10G)
#define FW2X_CTRL_EEE_MASK		\
	(FW2X_CTRL_10BASET_EEE |	\
	 FW2X_CTRL_100BASETX_EEE |	\
	 FW2X_CTRL_1000BASET_FD_EEE |	\
	 FW2X_CTRL_2P5GBASET_FD_EEE |	\
	 FW2X_CTRL_5GBASET_FD_EEE |	\
	 FW2X_CTRL_10GBASET_FD_EEE)

/* Hardware generation: Atlantic (AQ1) or Atlantic2 (AQ2). */
enum aq_hwtype {
	HWTYPE_AQ1,
	HWTYPE_AQ2
};

/* AQ1 bootloader variants (detected during firmware reboot). */
enum aq_fw_bootloader_mode {
	FW_BOOT_MODE_UNKNOWN = 0,
	FW_BOOT_MODE_FLB,		/* Flash Bootloader */
	FW_BOOT_MODE_RBL_FLASH,		/* ROM-Based Loader, from flash */
	FW_BOOT_MODE_RBL_HOST_BOOTLOAD	/* ROM-Based Loader, host boot */
};

enum aq_media_type {
	AQ_MEDIA_TYPE_UNKNOWN = 0,
	AQ_MEDIA_TYPE_FIBRE,
	AQ_MEDIA_TYPE_TP
};

/* Link speed flags (bitmask: multiple can be set for auto-negotiation). */
enum aq_link_speed {
	AQ_LINK_NONE    = 0,
	AQ_LINK_10M	= (1 << 0),
	AQ_LINK_100M    = (1 << 1),
	AQ_LINK_1G      = (1 << 2),
	AQ_LINK_2G5     = (1 << 3),
	AQ_LINK_5G      = (1 << 4),
	AQ_LINK_10G     = (1 << 5)
};

#define AQ_LINK_ALL	(AQ_LINK_100M | AQ_LINK_1G | AQ_LINK_2G5 | \
			    AQ_LINK_5G | AQ_LINK_10G )
#define AQ_LINK_AUTO	AQ_LINK_ALL

enum aq_link_eee {
	AQ_EEE_DISABLE = 0,
	AQ_EEE_ENABLE = 1
};

/* MPI (Management Processor Interface) firmware state machine. */
enum aq_hw_fw_mpi_state {
	MPI_DEINIT      = 0,	/* link down / inactive */
	MPI_RESET       = 1,
	MPI_INIT        = 2,	/* link active / configured */
	MPI_POWER       = 4
};

enum aq_link_fc {
        AQ_FC_NONE = 0,
        AQ_FC_RX = (1 << 0),
        AQ_FC_TX = (1 << 1),
        AQ_FC_ALL = (AQ_FC_RX | AQ_FC_TX)
};

#define AQ_SMB_START_TRANSMIT		0x5001
#define AQ_SMB_START_READ_TRANSMIT	0x5101
#define AQ_SMB_STOP_TRANSMIT		0x3001
#define AQ_SMB_REPEAT_TRANSMIT		0x1001
#define AQ_SMB_REPEAT_NACK_TRANSMIT	0x1011

/*
 * DMA memory descriptor.
 * Wraps the bus_dma(9) state needed for a contiguous DMA-accessible
 * memory region (used for TX/RX descriptor rings).
 */
struct aq_dmamem {
	bus_dmamap_t		aqm_map;	/* DMA mapping handle */
	bus_dma_segment_t	aqm_seg;	/* physical segment info */
	int			aqm_nsegs;	/* number of segments (1) */
	size_t			aqm_size;	/* allocation size in bytes */
	caddr_t			aqm_kva;	/* kernel virtual address */
};

#define AQ_DMA_MAP(_aqm)	((_aqm)->aqm_map)
#define AQ_DMA_DVA(_aqm)	((_aqm)->aqm_map->dm_segs[0].ds_addr) /* device-visible addr */
#define AQ_DMA_KVA(_aqm)	((void *)(_aqm)->aqm_kva) /* kernel-visible addr */
#define AQ_DMA_LEN(_aqm)	((_aqm)->aqm_size)


/*
 * Firmware mailbox structures.
 * AQ1 firmware uses a mailbox in device memory for communication.
 * The driver reads/writes dwords at the mailbox address (sc_mbox_addr)
 * using aq1_fw_downld_dwords().
 */
struct aq_mailbox_header {
        uint32_t version;
        uint32_t transaction_id;
        int32_t error;
} __packed __aligned(4);

/* Hardware statistics counters (unicast/multicast/broadcast pkt/byte counts) */
struct aq_hw_stats_s {
        uint32_t uprc;		/* unicast packets received */
        uint32_t mprc;		/* multicast packets received */
        uint32_t bprc;		/* broadcast packets received */
        uint32_t erpt;		/* TX errors */
        uint32_t uptc;		/* unicast packets transmitted */
        uint32_t mptc;		/* multicast packets transmitted */
        uint32_t bptc;		/* broadcast packets transmitted */
        uint32_t erpr;		/* RX errors */
        uint32_t mbtc;		/* multicast bytes transmitted */
        uint32_t bbtc;		/* broadcast bytes transmitted */
        uint32_t mbrc;		/* multicast bytes received */
        uint32_t bbrc;		/* broadcast bytes received */
        uint32_t ubrc;		/* unicast bytes received */
        uint32_t ubtc;		/* unicast bytes transmitted */
        uint32_t ptc;		/* total packets transmitted */
        uint32_t prc;		/* total packets received */
        uint32_t dpc;		/* dropped packet count (fw1x only) */
        uint32_t cprc;		/* checksum-verified pkts (fw1x only) */
} __packed __aligned(4);

struct aq_fw2x_capabilities {
        uint32_t caps_lo;
        uint32_t caps_hi;
} __packed __aligned(4);

struct aq_fw2x_msm_statistics {
	uint32_t uprc;
	uint32_t mprc;
	uint32_t bprc;
	uint32_t erpt;
	uint32_t uptc;
	uint32_t mptc;
	uint32_t bptc;
	uint32_t erpr;
	uint32_t mbtc;
	uint32_t bbtc;
	uint32_t mbrc;
	uint32_t bbrc;
	uint32_t ubrc;
	uint32_t ubtc;
	uint32_t ptc;
	uint32_t prc;
} __packed __aligned(4);

struct aq_fw2x_phy_cable_diag_data {
	uint32_t lane_data[4];
} __packed __aligned(4);

/*
 * FW2X mailbox layout in device memory (at sc_mbox_addr).
 * This is the firmware's host interface structure.  The driver reads
 * fields from it via aq1_fw_downld_dwords() to get statistics,
 * capabilities, and PHY diagnostic information.
 */
struct aq_fw2x_mailbox {		/* struct fwHostInterface */
	struct aq_mailbox_header header;
	struct aq_fw2x_msm_statistics msm;	/* MAC statistics */

	uint32_t phy_info1;
#define PHYINFO1_FAULT_CODE	__BITS(31,16)
#define PHYINFO1_PHY_H_BIT	__BITS(0,15)
	uint32_t phy_info2;
#define PHYINFO2_TEMPERATURE	__BITS(15,0)
#define PHYINFO2_CABLE_LEN	__BITS(23,16)

	struct aq_fw2x_phy_cable_diag_data diag_data;
	uint32_t reserved[8];

	struct aq_fw2x_capabilities caps;

	/* ... */
} __packed __aligned(4);

/*
 * Hardware descriptor formats.
 *
 * RX descriptors have two forms:
 *   - "read" format: driver writes buf_addr for the NIC to DMA into
 *   - "writeback" format: NIC writes status/length after receiving a packet
 * The same memory location is used for both; the NIC overwrites the
 * read descriptor with writeback data upon packet reception.
 *
 * TX descriptors come in two types:
 *   - TXD (data): points to a packet data buffer
 *   - TXC (context): carries VLAN tag or offload context
 */
struct aq_rx_desc_read {
	uint64_t		buf_addr;	/* DMA addr of receive buffer */
	uint64_t		hdr_addr;	/* header split addr (unused) */
} __packed;

struct aq_rx_desc_wb {
	uint32_t		type;		/* pkt type, RSS, VLAN, csum */
#define AQ_RXDESC_TYPE_RSSTYPE	0x000f
#define AQ_RXDESC_TYPE_ETHER	0x0030
#define AQ_RXDESC_TYPE_PROTO	0x01c0
#define AQ_RXDESC_TYPE_PROTO_TCP	(2 << 6)
#define AQ_RXDESC_TYPE_VLAN	(1 << 9)
#define AQ_RXDESC_TYPE_VLAN2	(1 << 10)
#define AQ_RXDESC_TYPE_DMA_ERR	(1 << 12)
#define AQ_RXDESC_TYPE_V4_SUM	(1 << 19)
#define AQ_RXDESC_TYPE_L4_SUM	(1 << 20)
	uint32_t		rss_hash;
	uint16_t		status;
#define AQ_RXDESC_STATUS_DD	(1 << 0)
#define AQ_RXDESC_STATUS_EOP	(1 << 1)
#define AQ_RXDESC_STATUS_MACERR (1 << 2)
#define AQ_RXDESC_STATUS_V4_SUM_NG (1 << 3)
#define AQ_RXDESC_STATUS_L4_SUM_ERR (1 << 4)
#define AQ_RXDESC_STATUS_L4_SUM_OK (1 << 5)
	uint16_t		pkt_len;
	uint16_t		next_desc_ptr;
	uint16_t		vlan;
} __packed;

struct aq_tx_desc {
	uint64_t		buf_addr;
	uint32_t		ctl1;
#define AQ_TXDESC_CTL1_TYPE_TXD	0x00000001
#define AQ_TXDESC_CTL1_TYPE_TXC	0x00000002
#define AQ_TXDESC_CTL1_BLEN_SHIFT 4
#define AQ_TXDESC_CTL1_VLAN_SHIFT 4
#define AQ_TXDESC_CTL1_DD	(1 << 20)
#define AQ_TXDESC_CTL1_CMD_EOP	(1 << 21)
#define AQ_TXDESC_CTL1_CMD_VLAN	(1 << 22)
#define AQ_TXDESC_CTL1_CMD_FCS	(1 << 23)
#define AQ_TXDESC_CTL1_CMD_IP4CSUM (1 << 24)
#define AQ_TXDESC_CTL1_CMD_L4CSUM (1 << 25)
#define AQ_TXDESC_CTL1_CMD_LSO	(1 << 26)
#define AQ_TXDESC_CTL1_CMD_WB	(1 << 27)

#define AQ_TXDESC_CTL1_VID_SHIFT 4
	uint32_t		ctl2;
#define AQ_TXDESC_CTL2_LEN_SHIFT 14
#define AQ_TXDESC_CTL2_CTX_EN	(1 << 13)

/* TXC context descriptor fields for LSO */
#define AQ_TXC_CTL1_CMD_SHIFT		20
#define AQ_TXC_CMD_LSO			0x4
#define AQ_TXC_CMD_IPV6			0x2
#define AQ_TXC_CTL1_L2LEN_SHIFT	24
#define AQ_TXC_CTL1_L3LEN_LSB		(1U << 31)
#define AQ_TXC_CTL2_L3LEN_SHIFT	0
#define AQ_TXC_CTL2_L4LEN_SHIFT	8
#define AQ_TXC_CTL2_MSS_SHIFT		16
} __packed;

/*
 * Per-descriptor slot: tracks the DMA mapping and mbuf for one
 * descriptor in a TX or RX ring.
 */
struct aq_slot {
	bus_dmamap_t		 as_map;	/* DMA map for this buffer */
	struct mbuf		*as_m;		/* associated mbuf (or NULL) */
};

/*
 * Per-queue receive ring state.
 * Each RX queue has a ring of AQ_RXD_NUM descriptors in DMA memory
 * (rx_mem), an array of per-slot tracking (rx_slots), producer/consumer
 * indices, and mbuf chain assembly state for multi-descriptor packets.
 */
struct aq_rxring {
	struct ifiqueue		*rx_ifiq;	/* associated input queue */
	struct aq_dmamem	 rx_mem;	/* DMA mem for descriptor ring */
	struct aq_slot		*rx_slots;	/* per-descriptor slot array */
	int			 rx_q;		/* hardware queue index */
	int			 rx_irq;	/* MSI-X vector for this queue */

	struct timeout		 rx_refill;	/* deferred refill timeout */
	struct if_rxring	 rx_rxr;	/* rxring accounting (MI) */
	uint32_t		 rx_prod;	/* producer: next to fill */
	uint32_t		 rx_cons;	/* consumer: next to reap */

	/* multi-descriptor packet assembly (jumbo frames span descs) */
	struct mbuf		*rx_m_head;	/* head of in-progress chain */
	struct mbuf		**rx_m_tail;	/* tail pointer for appending */
	int			 rx_m_error;	/* error seen on this pkt */
};

/*
 * Per-queue transmit ring state.
 * Each TX queue has a ring of AQ_TXD_NUM descriptors in DMA memory
 * and per-slot tracking for outstanding transmissions.
 */
struct aq_txring {
	struct ifqueue		*tx_ifq;	/* associated output queue */
	struct aq_dmamem	 tx_mem;	/* DMA mem for descriptor ring */
	struct aq_slot		*tx_slots;	/* per-descriptor slot array */
	int			 tx_q;		/* hardware queue index */
	int			 tx_irq;	/* MSI-X vector for this queue */
	uint32_t		 tx_prod;	/* producer: next to enqueue */
	uint32_t		 tx_cons;	/* consumer: next to reclaim */
};

/*
 * Per-queue state, combining one RX ring and one TX ring.
 * In multi-queue mode, each aq_queues gets its own MSI-X vector
 * and interrupt handler (aq_intr_queue), bound to a specific CPU.
 */
struct aq_queues {
	char			 q_name[16];	/* "aq0:0", "aq0:1", etc. */
	void			*q_ihc;		/* per-queue intr handle */
	struct aq_softc		*q_sc;		/* back-pointer to softc */
	int			 q_index;	/* queue index (0..nqueues-1) */
	struct aq_rxring 	 q_rx;
	struct aq_txring 	 q_tx;
};


/*
 * Firmware operations vtable.
 * Different firmware versions (1.x, 2.x/3.x, AQ2) use different
 * register interfaces.  This abstraction allows the common driver
 * code to work with any firmware variant.
 */
struct aq_softc;
struct aq_firmware_ops {
	int (*reset)(struct aq_softc *);
	int (*get_mac_addr)(struct aq_softc *);
	int (*set_mode)(struct aq_softc *, enum aq_hw_fw_mpi_state,
	    enum aq_link_speed, enum aq_link_fc, enum aq_link_eee);
	int (*get_mode)(struct aq_softc *, enum aq_hw_fw_mpi_state *,
	    enum aq_link_speed *, enum aq_link_fc *, enum aq_link_eee *);
	int (*get_stats)(struct aq_softc *, struct aq_hw_stats_s *);
};

/*
 * Driver softc (software context).
 * One per device instance, allocated by autoconf.  Contains all
 * per-device state: PCI handles, DMA tag, queue state, firmware
 * interface, media/link state, and the ifnet/arpcom for the
 * network stack.
 */
struct aq_softc {
	struct device		sc_dev;		/* base device (must be first) */
	uint16_t		sc_product;	/* PCI product ID */
	uint16_t		sc_revision;	/* PCI revision */
	bus_dma_tag_t		sc_dmat;	/* DMA tag for allocations */
	pci_chipset_tag_t	sc_pc;		/* PCI chipset handle */
	pcitag_t		sc_pcitag;	/* PCI device tag */
	int			sc_nqueues;	/* number of active queues */
	struct aq_queues	sc_queues[AQ_MAXQ];
	struct intrmap		*sc_intrmap;
	void			*sc_ih;
	bus_space_handle_t	sc_ioh;
	bus_space_tag_t		sc_iot;

	uint32_t		sc_mbox_addr;
	int			sc_rbl_enabled;
	int			sc_fast_start_enabled;
	int			sc_flash_present;
	int			sc_art_filter_base_index;
	uint32_t		sc_fw_version;
	const struct		aq_firmware_ops *sc_fw_ops;
	uint64_t		sc_fw_caps;
	enum aq_media_type	sc_media_type;
	enum aq_link_speed	sc_available_rates;
	uint32_t		sc_features;
	int			sc_linkstat_irq;
	struct arpcom		sc_arpcom;
	struct ifmedia		sc_media;

	struct ether_addr	sc_enaddr;
	struct mutex		sc_mpi_mutex;
};

/*
 * PCI device ID table for autoconf matching.
 * pci_matchbyid() checks if the attached PCI device matches any entry.
 */
const struct pci_matchid aq_devices[] = {
	{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC100 },
	{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC107 },
	{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC108 },
	{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC109 },
	{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC111 },
	{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC112 },
	{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC113 },
	{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC113C },
	{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC113CA },
	{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC113CS },
	{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC114CS },
	{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC115C },
	{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC116C },
	{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC100S },
	{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC107S },
	{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC108S },
	{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC109S },
	{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC111S },
	{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC112S },
	{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_D100 },
	{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_D107 },
	{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_D108 },
	{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_D109 },
};

/*
 * Product capability table.
 * Maps each PCI product ID to its hardware generation (AQ1/AQ2),
 * physical media type (copper/fibre), and supported link speeds.
 * aq_lookup() searches this table after a successful match.
 */
const struct aq_product {
	pci_vendor_id_t aq_vendor;
	pci_product_id_t aq_product;
	enum aq_hwtype aq_hwtype;
	enum aq_media_type aq_media_type;
	enum aq_link_speed aq_available_rates;
} aq_products[] = {
{	PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC100, HWTYPE_AQ1,
	AQ_MEDIA_TYPE_FIBRE, AQ_LINK_ALL
},
{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC107, HWTYPE_AQ1,
	AQ_MEDIA_TYPE_TP, AQ_LINK_ALL
},
{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC108, HWTYPE_AQ1,
	AQ_MEDIA_TYPE_TP, AQ_LINK_100M | AQ_LINK_1G | AQ_LINK_2G5 | AQ_LINK_5G
},
{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC109, HWTYPE_AQ1,
	AQ_MEDIA_TYPE_TP, AQ_LINK_100M | AQ_LINK_1G | AQ_LINK_2G5
},
{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC111, HWTYPE_AQ1,
	AQ_MEDIA_TYPE_TP, AQ_LINK_100M | AQ_LINK_1G | AQ_LINK_2G5 | AQ_LINK_5G
},
{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC112, HWTYPE_AQ1,
	AQ_MEDIA_TYPE_TP, AQ_LINK_100M | AQ_LINK_1G | AQ_LINK_2G5
},
{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC100S, HWTYPE_AQ1,
	AQ_MEDIA_TYPE_FIBRE, AQ_LINK_ALL
},
{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC107S, HWTYPE_AQ1,
	AQ_MEDIA_TYPE_TP, AQ_LINK_ALL
},
{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC108S, HWTYPE_AQ1,
	AQ_MEDIA_TYPE_TP, AQ_LINK_100M | AQ_LINK_1G | AQ_LINK_2G5 | AQ_LINK_5G
},
{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC109S, HWTYPE_AQ1,
	AQ_MEDIA_TYPE_TP, AQ_LINK_100M | AQ_LINK_1G | AQ_LINK_2G5
},
{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC111S, HWTYPE_AQ1,
	AQ_MEDIA_TYPE_TP, AQ_LINK_100M | AQ_LINK_1G | AQ_LINK_2G5 | AQ_LINK_5G
},
{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC112S, HWTYPE_AQ1,
	AQ_MEDIA_TYPE_TP, AQ_LINK_100M | AQ_LINK_1G | AQ_LINK_2G5
},
{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_D100, HWTYPE_AQ1,
	AQ_MEDIA_TYPE_FIBRE, AQ_LINK_ALL
},
{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_D107, HWTYPE_AQ1,
	AQ_MEDIA_TYPE_TP, AQ_LINK_ALL
},
{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_D108, HWTYPE_AQ1,
	AQ_MEDIA_TYPE_TP, AQ_LINK_100M | AQ_LINK_1G | AQ_LINK_2G5 | AQ_LINK_5G
},
{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_D109, HWTYPE_AQ1,
	AQ_MEDIA_TYPE_TP, AQ_LINK_100M | AQ_LINK_1G | AQ_LINK_2G5
},

{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC113, HWTYPE_AQ2,
	AQ_MEDIA_TYPE_TP, AQ_LINK_ALL | AQ_LINK_10M
},
{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC113C, HWTYPE_AQ2,
	AQ_MEDIA_TYPE_TP, AQ_LINK_ALL | AQ_LINK_10M
},
{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC113CA, HWTYPE_AQ2,
	AQ_MEDIA_TYPE_TP, AQ_LINK_ALL | AQ_LINK_10M
},
{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC113CS, HWTYPE_AQ2,
	AQ_MEDIA_TYPE_TP, AQ_LINK_ALL | AQ_LINK_10M
},
{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC114CS, HWTYPE_AQ2,
	AQ_MEDIA_TYPE_TP,
	AQ_LINK_10M | AQ_LINK_100M | AQ_LINK_1G | AQ_LINK_2G5 | AQ_LINK_5G
},
{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC115C, HWTYPE_AQ2,
	AQ_MEDIA_TYPE_TP,
	AQ_LINK_10M | AQ_LINK_100M | AQ_LINK_1G | AQ_LINK_2G5
},
{ PCI_VENDOR_AQUANTIA, PCI_PRODUCT_AQUANTIA_AQC116C, HWTYPE_AQ2,
	AQ_MEDIA_TYPE_TP, AQ_LINK_10M | AQ_LINK_100M | AQ_LINK_1G
},
};

int	aq_match(struct device *, void *, void *);
void	aq_attach(struct device *, struct device *, void *);
int	aq_activate(struct device *, int);
int	aq_intr(void *);
int	aq_intr_link(void *);
int	aq_intr_queue(void *);
int	aq_init_rss(struct aq_softc *);
int	aq_hw_reset(struct aq_softc *);
int	aq_hw_init(struct aq_softc *, int, int);
void	aq_hw_qos_set(struct aq_softc *);
void	aq_hw_init_tx_path(struct aq_softc *);
void	aq_hw_init_rx_path(struct aq_softc *);
int	aq_set_mac_addr(struct aq_softc *, int, uint8_t *);
int	aq_set_linkmode(struct aq_softc *, enum aq_link_speed,
    enum aq_link_fc, enum aq_link_eee);
void	aq_watchdog(struct ifnet *);
void	aq_enable_intr(struct aq_softc *, int, int);
int	aq_rxrinfo(struct aq_softc *, struct if_rxrinfo *);
int	aq_ioctl(struct ifnet *, u_long, caddr_t);
int	aq_up(struct aq_softc *);
void	aq_down(struct aq_softc *);
void	aq_iff(struct aq_softc *);
void	aq_start(struct ifqueue *);
void	aq_ifmedia_status(struct ifnet *, struct ifmediareq *);
int	aq_ifmedia_change(struct ifnet *);
void	aq_update_link_status(struct aq_softc *);
int	aq_get_sffpage(struct aq_softc *, struct if_sffpage *);

int	aq1_fw_reboot(struct aq_softc *);
int	aq1_fw_read_version(struct aq_softc *);
int	aq1_fw_version_init(struct aq_softc *);
int	aq1_hw_init_ucp(struct aq_softc *);
void	aq1_global_software_reset(struct aq_softc *);
int	aq1_mac_soft_reset(struct aq_softc *, enum aq_fw_bootloader_mode *);
int	aq1_mac_soft_reset_rbl(struct aq_softc *, enum aq_fw_bootloader_mode *);
int	aq1_mac_soft_reset_flb(struct aq_softc *);
int	aq1_fw_downld_dwords(struct aq_softc *, uint32_t, uint32_t *, uint32_t);

int	aq2_interface_buffer_read(struct aq_softc *, uint32_t, uint32_t *,
	    uint32_t);
int	aq2_fw_reboot(struct aq_softc *);
int	aq2_filter_art_set(struct aq_softc *, uint32_t, uint32_t, uint32_t,
	    uint32_t action);

void	aq_refill(void *);
int	aq_rx_fill(struct aq_softc *, struct aq_rxring *);
static inline unsigned int aq_rx_fill_slots(struct aq_softc *,
	    struct aq_rxring *, uint);

int	aq_dmamem_alloc(struct aq_softc *, struct aq_dmamem *,
	    bus_size_t, u_int);
void	aq_dmamem_free(struct aq_softc *, struct aq_dmamem *);

int	aq1_get_mac_addr(struct aq_softc *);

int	aq_fw1x_reset(struct aq_softc *);
int	aq_fw1x_get_mode(struct aq_softc *, enum aq_hw_fw_mpi_state *,
    enum aq_link_speed *, enum aq_link_fc *, enum aq_link_eee *);
int	aq_fw1x_set_mode(struct aq_softc *, enum aq_hw_fw_mpi_state,
    enum aq_link_speed, enum aq_link_fc, enum aq_link_eee);
int	aq_fw1x_get_stats(struct aq_softc *, struct aq_hw_stats_s *);

int	aq_fw2x_reset(struct aq_softc *);
int	aq_fw2x_get_mode(struct aq_softc *, enum aq_hw_fw_mpi_state *,
    enum aq_link_speed *, enum aq_link_fc *, enum aq_link_eee *);
int	aq_fw2x_set_mode(struct aq_softc *, enum aq_hw_fw_mpi_state,
    enum aq_link_speed, enum aq_link_fc, enum aq_link_eee);
int	aq_fw2x_get_stats(struct aq_softc *, struct aq_hw_stats_s *);

int	aq2_fw_reset(struct aq_softc *);
int	aq2_get_mac_addr(struct aq_softc *);
int	aq2_fw_get_mode(struct aq_softc *, enum aq_hw_fw_mpi_state *,
	    enum aq_link_speed *, enum aq_link_fc *, enum aq_link_eee *);
int	aq2_fw_set_mode(struct aq_softc *, enum aq_hw_fw_mpi_state,
	    enum aq_link_speed, enum aq_link_fc, enum aq_link_eee);
int	aq2_fw_get_stats(struct aq_softc *, struct aq_hw_stats_s *);

/*
 * Firmware ops for each firmware generation.
 * fw1x: AQ1 firmware version 1.x (mostly stubs, limited support)
 * fw2x: AQ1 firmware version 2.x/3.x (full support)
 * aq2:  AQ2 firmware (completely different register interface)
 */
const struct aq_firmware_ops aq_fw1x_ops = {
	.reset = aq_fw1x_reset,
	.get_mac_addr = aq1_get_mac_addr,
	.set_mode = aq_fw1x_set_mode,
	.get_mode = aq_fw1x_get_mode,
	.get_stats = aq_fw1x_get_stats,
};

const struct aq_firmware_ops aq_fw2x_ops = {
	.reset = aq_fw2x_reset,
	.get_mac_addr = aq1_get_mac_addr,
	.set_mode = aq_fw2x_set_mode,
	.get_mode = aq_fw2x_get_mode,
	.get_stats = aq_fw2x_get_stats,
};

const struct aq_firmware_ops aq2_fw_ops = {
	.reset = aq2_fw_reset,
	.get_mac_addr = aq2_get_mac_addr,
	.set_mode = aq2_fw_set_mode,
	.get_mode = aq2_fw_get_mode,
	.get_stats = aq2_fw_get_stats
};

/*
 * OpenBSD autoconf(9) attachment glue.
 *
 * cfattach: specifies softc size, match/attach/activate functions.
 * cfdriver: specifies driver name ("aq") and type (DV_IFNET = network).
 *
 * The kernel calls aq_match() for each PCI device to check if this
 * driver handles it, then aq_attach() to initialize a matched device.
 */
const struct cfattach aq_ca = {
	sizeof(struct aq_softc), aq_match, aq_attach, NULL,
	aq_activate
};

struct cfdriver aq_cd = {
	NULL, "aq", DV_IFNET
};

/*
 * Autoconf match function.
 * Called by the PCI bus driver for each device.  Returns nonzero if
 * this driver can handle the device (checks vendor/product against
 * aq_devices table).
 */
int
aq_match(struct device *dev, void *match, void *aux)
{
	return pci_matchbyid((struct pci_attach_args *)aux, aq_devices,
	    sizeof(aq_devices) / sizeof(aq_devices[0]));
}

/*
 * Look up product-specific capabilities (hw type, media, speeds)
 * for a matched device.
 */
const struct aq_product *
aq_lookup(const struct pci_attach_args *pa)
{
	unsigned int i;

	for (i = 0; i < sizeof(aq_products) / sizeof(aq_products[0]); i++) {
	if (PCI_VENDOR(pa->pa_id) == aq_products[i].aq_vendor &&
		PCI_PRODUCT(pa->pa_id) == aq_products[i].aq_product) {
			return &aq_products[i];
		}
	}

	return NULL;
}

/*
 * Autoconf attach function - main driver initialization.
 *
 * Called once for each matched PCI device.  Performs the full
 * initialization sequence:
 *   1. Map PCI BAR0 (MMIO register space)
 *   2. Set up interrupts (MSI-X preferred, then MSI, then legacy)
 *   3. Boot/reset the on-chip firmware
 *   4. Reset and initialize the hardware
 *   5. Read the MAC address from firmware/EEPROM
 *   6. Initialize RSS (Receive Side Scaling)
 *   7. Register the network interface with the kernel (if_attach)
 *   8. Set up per-queue interrupt handlers and moderation
 */
void
aq_attach(struct device *parent, struct device *self, void *aux)
{
	struct aq_softc *sc = (struct aq_softc *)self;
	struct pci_attach_args *pa = aux;
	const struct aq_product *aqp;
	pcireg_t bar, memtype;
	pci_chipset_tag_t pc;
	pci_intr_handle_t ih;
	int (*isr)(void *);
	const char *intrstr;
	pcitag_t tag;
	struct ifnet *ifp = &sc->sc_arpcom.ac_if;
	int txmin, txmax, rxmin, rxmax;
	int irqmode, irqnum;
	int i;

	mtx_init(&sc->sc_mpi_mutex, IPL_NET);

	sc->sc_dmat = pa->pa_dmat;
	sc->sc_pc = pc = pa->pa_pc;
	sc->sc_pcitag = tag = pa->pa_tag;

	sc->sc_product = PCI_PRODUCT(pa->pa_id);
	sc->sc_revision = PCI_REVISION(pa->pa_class);

	aqp = aq_lookup(pa);

	bar = pci_conf_read(pc, tag, AQ_BAR0);
	if (PCI_MAPREG_TYPE(bar) != PCI_MAPREG_TYPE_MEM) {
		printf(": wrong BAR type\n");
		return;
	}

	memtype = pci_mapreg_type(pc, tag, AQ_BAR0);
	if (pci_mapreg_map(pa, AQ_BAR0, memtype, 0, &sc->sc_iot, &sc->sc_ioh,
	    NULL, NULL, 0)) {
		printf(": failed to map BAR0\n");
		return;
	}

	/*
	 * Interrupt setup.
	 *
	 * Try MSI-X first (preferred for multi-queue).  If we get >1
	 * MSI-X vector, reserve vector 0 for link status interrupts
	 * and use the remaining vectors for per-queue TX/RX completion.
	 * intrmap_create() determines how many queues to use based on
	 * available vectors and CPU count.
	 *
	 * Fall back to MSI (single vector) or legacy INTx if MSI-X
	 * is not available.  In these modes we use a single queue and
	 * a combined interrupt handler (aq_intr).
	 */
	sc->sc_nqueues = 1;
	sc->sc_linkstat_irq = AQ_LINKSTAT_IRQ;
	isr = aq_intr;
	irqnum = 0;

	if (pci_intr_map_msix(pa, 0, &ih) == 0) {
		int nmsix = pci_intr_msix_count(pa);
		if (nmsix > 1) {
			/* Reserve vector 0 for link; rest for queues */
			nmsix--;
			sc->sc_intrmap = intrmap_create(&sc->sc_dev, nmsix,
			    MIN(AQ_MAXQ, IF_MAX_VECTORS), INTRMAP_POWEROF2);
			sc->sc_nqueues = intrmap_count(sc->sc_intrmap);
			KASSERT(sc->sc_nqueues > 0);
			KASSERT(powerof2(sc->sc_nqueues));

			sc->sc_linkstat_irq = 0;  /* link on vector 0 */
			isr = aq_intr_link;       /* vector 0 handler */
			irqnum++;                 /* queues start at 1 */
		}
		irqmode = AQ_INTR_CTRL_IRQMODE_MSIX;
	} else if (pci_intr_map_msi(pa, &ih) == 0) {
		irqmode = AQ_INTR_CTRL_IRQMODE_MSI;
	} else if (pci_intr_map(pa, &ih) == 0) {
		irqmode = AQ_INTR_CTRL_IRQMODE_LEGACY;
	} else {
		printf(": failed to map interrupt\n");
		return;
	}

	/* Establish the primary interrupt handler (link or combined) */
	sc->sc_ih = pci_intr_establish(pa->pa_pc, ih,
	    IPL_NET | IPL_MPSAFE, isr, sc, self->dv_xname);
	intrstr = pci_intr_string(pa->pa_pc, ih);
	if (intrstr)
		printf(": %s", intrstr);

	if (sc->sc_nqueues > 1)
		printf(", %d queues", sc->sc_nqueues);

	switch (aqp->aq_hwtype) {
	case HWTYPE_AQ1:
		if (aq1_fw_reboot(sc))
			return;
		break;
	case HWTYPE_AQ2:
		if (aq2_fw_reboot(sc))
			return;
		break;
	default:
		return;
	}

	if (aq_hw_reset(sc))
		return;

	if (sc->sc_fw_ops->get_mac_addr(sc))
		return;
	printf(", address %s", ether_sprintf(sc->sc_enaddr.ether_addr_octet));

	if (aq_init_rss(sc))
		return;

	if (aq_hw_init(sc, irqmode, (sc->sc_nqueues > 1)))
		return;

	sc->sc_media_type = aqp->aq_media_type;
	sc->sc_available_rates = aqp->aq_available_rates;

	/*
	 * Register the network interface with the kernel.
	 *
	 * if_flags: BROADCAST (can send to all), MULTICAST (group addr),
	 *           SIMPLEX (can't hear own transmissions).
	 * if_xflags: MPSAFE = this driver's entry points are MP-safe
	 *            (use per-queue locks, not the kernel lock).
	 * if_qstart: per-queue transmit function (called by ifq_start).
	 * if_hardmtu: maximum MTU the hardware supports (9000 = jumbo).
	 * if_capabilities: hardware offload features advertised to stack.
	 */
	ifmedia_init(&sc->sc_media, IFM_IMASK, aq_ifmedia_change,
	    aq_ifmedia_status);

	bcopy(sc->sc_enaddr.ether_addr_octet, sc->sc_arpcom.ac_enaddr, 6);
	strlcpy(ifp->if_xname, self->dv_xname, IFNAMSIZ);
	ifp->if_softc = sc;
	ifp->if_flags = IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX;
	ifp->if_xflags = IFXF_MPSAFE;
	ifp->if_ioctl = aq_ioctl;
	ifp->if_qstart = aq_start;
	ifp->if_watchdog = aq_watchdog;
	ifp->if_hardmtu = 9000;
	ifp->if_capabilities = IFCAP_VLAN_MTU | IFCAP_CSUM_IPv4 |
	    IFCAP_CSUM_UDPv4 | IFCAP_CSUM_UDPv6 | IFCAP_CSUM_TCPv4 |
	    IFCAP_CSUM_TCPv6 | IFCAP_TSOv4 | IFCAP_TSOv6;
	ifp->if_capabilities |= IFCAP_LRO;
	ifp->if_xflags |= IFXF_LRO;
#if NVLAN > 0
	ifp->if_capabilities |= IFCAP_VLAN_HWTAGGING;
#endif
	ifq_init_maxlen(&ifp->if_snd, AQ_TXD_NUM);

	ifmedia_init(&sc->sc_media, IFM_IMASK, aq_ifmedia_change,
	    aq_ifmedia_status);
	if (sc->sc_available_rates & AQ_LINK_10M) {
		ifmedia_add(&sc->sc_media, IFM_ETHER|IFM_10_T, 0, NULL);
		ifmedia_add(&sc->sc_media, IFM_ETHER|IFM_10_T|IFM_FDX, 0,
		    NULL);
	}

	if (sc->sc_available_rates & AQ_LINK_100M) {
		ifmedia_add(&sc->sc_media, IFM_ETHER|IFM_100_TX, 0, NULL);
		ifmedia_add(&sc->sc_media, IFM_ETHER|IFM_100_TX|IFM_FDX, 0,
		    NULL);
	}

	if (sc->sc_available_rates & AQ_LINK_1G) {
		ifmedia_add(&sc->sc_media, IFM_ETHER|IFM_1000_T, 0, NULL);
		ifmedia_add(&sc->sc_media, IFM_ETHER|IFM_1000_T|IFM_FDX, 0,
		    NULL);
	}

	if (sc->sc_available_rates & AQ_LINK_2G5) {
		ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_2500_T, 0, NULL);
		ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_2500_T | IFM_FDX,
		    0, NULL);
	}

	if (sc->sc_available_rates & AQ_LINK_5G) {
		ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_5000_T, 0, NULL);
		ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_5000_T | IFM_FDX,
		    0, NULL);
	}

	if (sc->sc_available_rates & AQ_LINK_10G) {
		ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_10G_T, 0, NULL);
		ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_10G_T | IFM_FDX,
		    0, NULL);
	}

	ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_AUTO, 0, NULL);
	ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_AUTO | IFM_FDX, 0, NULL);
	ifmedia_set(&sc->sc_media, IFM_ETHER | IFM_AUTO);
	aq_set_linkmode(sc, AQ_LINK_AUTO, AQ_FC_NONE, AQ_EEE_DISABLE);

        if_attach(ifp);
        ether_ifattach(ifp);

	if_attach_iqueues(ifp, sc->sc_nqueues);
	if_attach_queues(ifp, sc->sc_nqueues);

	/*
	 * set interrupt moderation for up to 20k interrupts per second,
	 * more rx than tx.  these values are in units of 2us.
	 */
	txmin = 20;
	txmax = 200;
	rxmin = 6;
	rxmax = 60;

	for (i = 0; i < sc->sc_nqueues; i++) {
		struct aq_queues *aq = &sc->sc_queues[i];
		struct aq_rxring *rx = &aq->q_rx;
		struct aq_txring *tx = &aq->q_tx;
		pci_intr_handle_t ih;

		aq->q_sc = sc;
		aq->q_index = i;
		rx->rx_q = i;
		rx->rx_ifiq = ifp->if_iqs[i];
		rx->rx_m_head = NULL;
		rx->rx_m_tail = &rx->rx_m_head;
		rx->rx_m_error = 0;
		ifp->if_iqs[i]->ifiq_softc = aq;
		timeout_set(&rx->rx_refill, aq_refill, rx);

		tx->tx_q = i;
		tx->tx_ifq = ifp->if_ifqs[i];
		ifp->if_ifqs[i]->ifq_softc = aq;

		snprintf(aq->q_name, sizeof(aq->q_name), "%s:%u",
		    DEVNAME(sc), i);

		if (sc->sc_nqueues > 1) {
			if (pci_intr_map_msix(pa, irqnum, &ih)) {
				printf(": unable to map msi-x vector %d\n",
				    irqnum);
				return;
			}

			aq->q_ihc = pci_intr_establish_cpu(sc->sc_pc, ih,
			    IPL_NET | IPL_MPSAFE, intrmap_cpu(sc->sc_intrmap, i),
			    aq_intr_queue, aq, aq->q_name);
			if (aq->q_ihc == NULL) {
				printf(": unable to establish interrupt %d\n",
				    irqnum);
				return;
			}
			rx->rx_irq = irqnum;
			tx->tx_irq = irqnum;
			irqnum++;
		} else {
			rx->rx_irq = irqnum++;
			tx->tx_irq = irqnum++;
		}

		if (HWTYPE_AQ2_P(sc)) {
			AQ_WRITE_REG_BIT(sc, AQ2_TX_INTR_MODERATION_CTL_REG(i),
			    AQ2_TX_INTR_MODERATION_CTL_MIN, txmin);
			AQ_WRITE_REG_BIT(sc, AQ2_TX_INTR_MODERATION_CTL_REG(i),
			    AQ2_TX_INTR_MODERATION_CTL_MAX, txmax);
			AQ_WRITE_REG_BIT(sc, AQ2_TX_INTR_MODERATION_CTL_REG(i),
			    AQ2_TX_INTR_MODERATION_CTL_EN, 1);
		} else {
			AQ_WRITE_REG_BIT(sc, TX_INTR_MODERATION_CTL_REG(i),
			    TX_INTR_MODERATION_CTL_MIN, txmin);
			AQ_WRITE_REG_BIT(sc, TX_INTR_MODERATION_CTL_REG(i),
			    TX_INTR_MODERATION_CTL_MAX, txmax);
			AQ_WRITE_REG_BIT(sc, TX_INTR_MODERATION_CTL_REG(i),
			    TX_INTR_MODERATION_CTL_EN, 1);
		}
		AQ_WRITE_REG_BIT(sc, RX_INTR_MODERATION_CTL_REG(i),
		    RX_INTR_MODERATION_CTL_MIN, rxmin);
		AQ_WRITE_REG_BIT(sc, RX_INTR_MODERATION_CTL_REG(i),
		    RX_INTR_MODERATION_CTL_MAX, rxmax);
		AQ_WRITE_REG_BIT(sc, RX_INTR_MODERATION_CTL_REG(i),
		    RX_INTR_MODERATION_CTL_EN, 1);
	}

	AQ_WRITE_REG_BIT(sc, TX_DMA_INT_DESC_WRWB_EN_REG,
	    TX_DMA_INT_DESC_WRWB_EN, 0);
	AQ_WRITE_REG_BIT(sc, TX_DMA_INT_DESC_WRWB_EN_REG,
	    TX_DMA_INT_DESC_MODERATE_EN, 1);
	AQ_WRITE_REG_BIT(sc, RX_DMA_INT_DESC_WRWB_EN_REG,
	    RX_DMA_INT_DESC_WRWB_EN, 0);
	AQ_WRITE_REG_BIT(sc, RX_DMA_INT_DESC_WRWB_EN_REG,
	    RX_DMA_INT_DESC_MODERATE_EN, 1);

	aq_enable_intr(sc, 1, 0);
	printf("\n");
}

/*
 * AQ1 firmware boot sequence.
 *
 * AQ1 devices have two bootloader modes:
 *   - FLB (Flash Bootloader): firmware loaded directly from SPI flash
 *   - RBL (ROM-Based Loader): a ROM loads firmware from flash or host
 *
 * This function detects which mode is in use, performs the appropriate
 * reset sequence, reads the firmware version, selects the fw ops
 * (fw1x vs fw2x), detects the chip revision, and initializes the
 * firmware coprocessor (UCP).
 */
int
aq1_fw_reboot(struct aq_softc *sc)
{
	uint32_t ver, v, boot_exit_code;
	int i, error;
	enum aq_fw_bootloader_mode mode;

	mode = FW_BOOT_MODE_UNKNOWN;

	ver = AQ_READ_REG(sc, AQ_FW_VERSION_REG);

	for (i = 1000; i > 0; i--) {
		v = AQ_READ_REG(sc, FW_MPI_DAISY_CHAIN_STATUS_REG);
		boot_exit_code = AQ_READ_REG(sc, FW_BOOT_EXIT_CODE_REG);
		if (v != 0x06000000 || boot_exit_code != 0)
			break;
	}

	if (i <= 0) {
		printf(": F/W reset failed. Neither RBL nor FLB started");
		return ETIMEDOUT;
	}

	sc->sc_rbl_enabled = (boot_exit_code != 0);

	/*
	 * Having FW version 0 is an indicator that cold start
	 * is in progress. This means two things:
	 * 1) Driver have to wait for FW/HW to finish boot (500ms giveup)
	 * 2) Driver may skip reset sequence and save time.
	 */
	if (sc->sc_fast_start_enabled && (ver != 0)) {
		if (aq1_fw_read_version(sc) == 0)
			goto faststart;
	}

	error = aq1_mac_soft_reset(sc, &mode);
	if (error != 0) {
		printf("%s: MAC reset failed: %d\n", DEVNAME(sc), error);
		return error;
	}

	switch (mode) {
	case FW_BOOT_MODE_FLB:
		DPRINTF(("%s: FLB> F/W successfully loaded from flash.",
		    DEVNAME(sc)));
		sc->sc_flash_present = 1;
		break;
	case FW_BOOT_MODE_RBL_FLASH:
		DPRINTF(("%s: RBL> F/W loaded from flash. Host Bootload "
		    "disabled.", DEVNAME(sc)));
		sc->sc_flash_present = 1;
		break;
	case FW_BOOT_MODE_UNKNOWN:
		printf("%s: F/W bootload error: unknown bootloader type",
		    DEVNAME(sc));
		return ENOTSUP;
	case FW_BOOT_MODE_RBL_HOST_BOOTLOAD:
		printf("%s: RBL> F/W Host Bootload not implemented", DEVNAME(sc));
		return ENOTSUP;
	}

 faststart:
	error = aq1_fw_read_version(sc);
	if (error != 0)
		return error;

	error = aq1_fw_version_init(sc);
	if (error != 0)
		return error;

	return aq1_hw_init_ucp(sc);
}

/*
 * AQ1 MAC soft reset using the ROM-Based Loader (RBL).
 * Issues a global software reset, then waits for the RBL to reload
 * firmware from flash.  Returns the boot mode (flash or host bootload).
 */
int
aq1_mac_soft_reset_rbl(struct aq_softc *sc, enum aq_fw_bootloader_mode *mode)
{
	int timo;

	DPRINTF(("%s: RBL> MAC reset STARTED!\n", DEVNAME(sc)));

	AQ_WRITE_REG(sc, AQ_FW_GLB_CTL2_REG, 0x40e1);
	AQ_WRITE_REG(sc, AQ_FW_GLB_CPU_SEM_REG(0), 1);
	AQ_WRITE_REG(sc, AQ_MBOXIF_POWER_GATING_CONTROL_REG, 0);

	/* MAC FW will reload PHY FW if 1E.1000.3 was cleaned - #undone */
	AQ_WRITE_REG(sc, FW_BOOT_EXIT_CODE_REG, RBL_STATUS_DEAD);

	aq1_global_software_reset(sc);

	AQ_WRITE_REG(sc, AQ_FW_GLB_CTL2_REG, 0x40e0);

	/* Wait for RBL to finish boot process. */
#define RBL_TIMEOUT_MS	10000
	uint16_t rbl_status;
	for (timo = RBL_TIMEOUT_MS; timo > 0; timo--) {
		rbl_status = AQ_READ_REG(sc, FW_BOOT_EXIT_CODE_REG) & 0xffff;
		if (rbl_status != 0 && rbl_status != RBL_STATUS_DEAD)
			break;
		delay(1000);
	}

	if (timo <= 0) {
		printf("%s: RBL> RBL restart failed: timeout\n", DEVNAME(sc));
		return EBUSY;
	}

	switch (rbl_status) {
	case RBL_STATUS_SUCCESS:
		if (mode != NULL)
			*mode = FW_BOOT_MODE_RBL_FLASH;
		DPRINTF(("%s: RBL> reset complete! [Flash]\n", DEVNAME(sc)));
		break;
	case RBL_STATUS_HOST_BOOT:
		if (mode != NULL)
			*mode = FW_BOOT_MODE_RBL_HOST_BOOTLOAD;
		DPRINTF(("%s: RBL> reset complete! [Host Bootload]\n",
		    DEVNAME(sc)));
		break;
	case RBL_STATUS_FAILURE:
	default:
		printf("%s: unknown RBL status 0x%x\n", DEVNAME(sc),
		    rbl_status);
		return EBUSY;
	}

	return 0;
}

/*
 * AQ1 MAC soft reset using the Flash Bootloader (FLB).
 * Clears the SPI interface, kicks the MAC, performs a global software
 * reset, and waits for firmware to start.  More complex than RBL due
 * to the need to manually manage SPI flash recovery.
 */
int
aq1_mac_soft_reset_flb(struct aq_softc *sc)
{
	uint32_t v;
	int timo;

	AQ_WRITE_REG(sc, AQ_FW_GLB_CTL2_REG, 0x40e1);
	/*
	 * Let Felicity hardware to complete SMBUS transaction before
	 * Global software reset.
	 */
	delay(50000);

	/*
	 * If SPI burst transaction was interrupted(before running the script),
	 * global software reset may not clear SPI interface.
	 * Clean it up manually before global reset.
	 */
	AQ_WRITE_REG(sc, AQ_GLB_NVR_PROVISIONING2_REG, 0x00a0);
	AQ_WRITE_REG(sc, AQ_GLB_NVR_INTERFACE1_REG, 0x009f);
	AQ_WRITE_REG(sc, AQ_GLB_NVR_INTERFACE1_REG, 0x809f);
	delay(50000);

	v = AQ_READ_REG(sc, AQ_FW_SOFTRESET_REG);
	v &= ~AQ_FW_SOFTRESET_DIS;
	v |= AQ_FW_SOFTRESET_RESET;
	AQ_WRITE_REG(sc, AQ_FW_SOFTRESET_REG, v);

	/* Kickstart. */
	AQ_WRITE_REG(sc, AQ_FW_GLB_CTL2_REG, 0x80e0);
	AQ_WRITE_REG(sc, AQ_MBOXIF_POWER_GATING_CONTROL_REG, 0);
	if (!sc->sc_fast_start_enabled)
		AQ_WRITE_REG(sc, AQ_GLB_GENERAL_PROVISIONING9_REG, 1);

	/*
	 * For the case SPI burst transaction was interrupted (by MCP reset
	 * above), wait until it is completed by hardware.
	 */
	delay(50000);

	/* MAC Kickstart */
	if (!sc->sc_fast_start_enabled) {
		AQ_WRITE_REG(sc, AQ_FW_GLB_CTL2_REG, 0x180e0);

		uint32_t flb_status;
		for (timo = 0; timo < 1000; timo++) {
			flb_status = AQ_READ_REG(sc,
			    FW_MPI_DAISY_CHAIN_STATUS_REG) & 0x10;
			if (flb_status != 0)
				break;
			delay(1000);
		}
		if (flb_status == 0) {
			printf("%s: FLB> MAC kickstart failed: timed out\n",
			    DEVNAME(sc));
			return ETIMEDOUT;
		}
		DPRINTF(("%s: FLB> MAC kickstart done, %d ms\n", DEVNAME(sc),
		    timo));
		/* FW reset */
		AQ_WRITE_REG(sc, AQ_FW_GLB_CTL2_REG, 0x80e0);
		/*
		 * Let Felicity hardware complete SMBUS transaction before
		 * Global software reset.
		 */
		delay(50000);
		sc->sc_fast_start_enabled = true;
	}
	AQ_WRITE_REG(sc, AQ_FW_GLB_CPU_SEM_REG(0), 1);

	/* PHY Kickstart: #undone */
	aq1_global_software_reset(sc);

	for (timo = 0; timo < 1000; timo++) {
		if (AQ_READ_REG(sc, AQ_FW_VERSION_REG) != 0)
			break;
		delay(10000);
	}
	if (timo >= 1000) {
		printf("%s: FLB> Global Soft Reset failed\n", DEVNAME(sc));
		return ETIMEDOUT;
	}
	DPRINTF(("%s: FLB> F/W restart: %d ms\n", DEVNAME(sc), timo * 10));

	return 0;

}

/* Choose the appropriate reset method (RBL or FLB) for AQ1 devices. */
int
aq1_mac_soft_reset(struct aq_softc *sc, enum aq_fw_bootloader_mode *mode)
{
	if (sc->sc_rbl_enabled)
		return aq1_mac_soft_reset_rbl(sc, mode);

	if (mode != NULL)
		*mode = FW_BOOT_MODE_FLB;
	return aq1_mac_soft_reset_flb(sc);
}

/* Trigger a full global software reset of the AQ1 hardware. */
void
aq1_global_software_reset(struct aq_softc *sc)
{
        uint32_t v;

        AQ_WRITE_REG_BIT(sc, RX_SYSCONTROL_REG, RX_SYSCONTROL_RESET_DIS, 0);
        AQ_WRITE_REG_BIT(sc, TX_SYSCONTROL_REG, TX_SYSCONTROL_RESET_DIS, 0);
        AQ_WRITE_REG_BIT(sc, FW_MPI_RESETCTRL_REG,
            FW_MPI_RESETCTRL_RESET_DIS, 0);

        v = AQ_READ_REG(sc, AQ_FW_SOFTRESET_REG);
        v &= ~AQ_FW_SOFTRESET_DIS;
        v |= AQ_FW_SOFTRESET_RESET;
        AQ_WRITE_REG(sc, AQ_FW_SOFTRESET_REG, v);
}

/* Wait for firmware to write its version number, then read it. */
int
aq1_fw_read_version(struct aq_softc *sc)
{
	int i, error = EBUSY;
#define MAC_FW_START_TIMEOUT_MS 10000
	for (i = 0; i < MAC_FW_START_TIMEOUT_MS; i++) {
		sc->sc_fw_version = AQ_READ_REG(sc, AQ_FW_VERSION_REG);
		if (sc->sc_fw_version != 0) {
			error = 0;
			break;
		}
		delay(1000);
	}
	return error;
}

/*
 * Select firmware ops based on version, detect chip revision.
 * FW version 1.x -> fw1x_ops, 2.x/3.x -> fw2x_ops.
 * Chip revision (A0, B0, B1) determines which features are available.
 */
int
aq1_fw_version_init(struct aq_softc *sc)
{
	int error = 0;
	char fw_vers[sizeof("F/W version xxxxx.xxxxx.xxxxx")];

	if (FW_VERSION_MAJOR(sc) == 1) {
		sc->sc_fw_ops = &aq_fw1x_ops;
	} else if ((FW_VERSION_MAJOR(sc) == 2) || (FW_VERSION_MAJOR(sc) == 3)) {
		sc->sc_fw_ops = &aq_fw2x_ops;
	} else {
		printf(": Unsupported F/W version %d.%d.%d\n",
		    FW_VERSION_MAJOR(sc), FW_VERSION_MINOR(sc),
		    FW_VERSION_BUILD(sc));
		return ENOTSUP;
	}
	snprintf(fw_vers, sizeof(fw_vers), "F/W version %d.%d.%d",
	    FW_VERSION_MAJOR(sc), FW_VERSION_MINOR(sc), FW_VERSION_BUILD(sc));

	/* detect revision */
	uint32_t hwrev = AQ_READ_REG(sc, AQ_HW_REVISION_REG);
	switch (hwrev & 0x0000000f) {
	case 0x01:
		printf(", Atlantic A0, %s", fw_vers);
		sc->sc_features |= FEATURES_AQ1_REV_A0 |
		    FEATURES_MPI_AQ | FEATURES_MIPS;
		break;
	case 0x02:
		printf(", Atlantic B0, %s", fw_vers);
		sc->sc_features |= FEATURES_AQ1_REV_B0 |
		    FEATURES_MPI_AQ | FEATURES_MIPS |
		    FEATURES_TPO2 | FEATURES_RPF2;
		break;
	case 0x0A:
		printf(", Atlantic B1, %s", fw_vers);
		sc->sc_features |= FEATURES_AQ1_REV_B1 |
		    FEATURES_MPI_AQ | FEATURES_MIPS |
		    FEATURES_TPO2 | FEATURES_RPF2;
		break;
	default:
		printf(": Unknown revision (0x%08x)\n", hwrev);
		error = ENOTSUP;
		break;
	}
	return error;
}

/*
 * Initialize the AQ1 microcontroller/coprocessor (UCP).
 * For fw1x, generates a random MAC seed if needed and waits for the
 * firmware mailbox address to become available.  Also enforces a
 * minimum firmware version requirement.
 */
int
aq1_hw_init_ucp(struct aq_softc *sc)
{
	int timo;

	if (FW_VERSION_MAJOR(sc) == 1) {
		if (AQ_READ_REG(sc, FW1X_MPI_INIT2_REG) == 0) {
			uint32_t data;
			arc4random_buf(&data, sizeof(data));
			data &= 0xfefefefe;
			data |= 0x02020202;
			AQ_WRITE_REG(sc, FW1X_MPI_INIT2_REG, data);
		}
		AQ_WRITE_REG(sc, FW1X_MPI_INIT1_REG, 0);
	}

	for (timo = 100; timo > 0; timo--) {
		sc->sc_mbox_addr = AQ_READ_REG(sc, FW_MPI_MBOX_ADDR_REG);
		if (sc->sc_mbox_addr != 0)
			break;
		delay(1000);
	}

#define AQ_FW_MIN_VERSION	0x01050006
#define AQ_FW_MIN_VERSION_STR	"1.5.6"
	if (sc->sc_fw_version < AQ_FW_MIN_VERSION) {
		printf("%s: atlantic: wrong FW version: " AQ_FW_MIN_VERSION_STR
		    " or later required, this is %d.%d.%d\n",
		    DEVNAME(sc),
		    FW_VERSION_MAJOR(sc),
		    FW_VERSION_MINOR(sc),
		    FW_VERSION_BUILD(sc));
		return ENOTSUP;
	}

	if (sc->sc_mbox_addr == 0)
		printf("%s: NULL MBOX!!\n", DEVNAME(sc));

	return 0;
}

/*
 * Read from the AQ2 firmware shared memory interface.
 * AQ2 firmware uses a producer-consumer transaction ID scheme for
 * coherency: the driver reads the transaction ID before and after
 * the data read; if they match, the data is consistent.  Retries
 * if the firmware was updating the buffer mid-read.
 */
int
aq2_interface_buffer_read(struct aq_softc *sc, uint32_t reg0, uint32_t *data0,
    uint32_t size0)
{
	uint32_t tid0, tid1, reg, *data, size;
	int timo;

	for (timo = 10000; timo > 0; timo--) {
		tid0 = AQ_READ_REG(sc, AQ2_FW_INTERFACE_OUT_TRANSACTION_ID_REG);
		if (((tid0 & AQ2_FW_INTERFACE_OUT_TRANSACTION_ID_A)
		    >> AQ2_FW_INTERFACE_OUT_TRANSACTION_ID_A_S) !=
		    ((tid0 & AQ2_FW_INTERFACE_OUT_TRANSACTION_ID_B)
		    >> AQ2_FW_INTERFACE_OUT_TRANSACTION_ID_B_S)) {
			delay(10);
			continue;
		}

		for (reg = reg0, data = data0, size = size0;
		    size >= 4; reg += 4, data++, size -= 4) {
			*data = AQ_READ_REG(sc, reg);
		}

		tid1 = AQ_READ_REG(sc, AQ2_FW_INTERFACE_OUT_TRANSACTION_ID_REG);
		if (tid0 == tid1)
			break;
	}
	if (timo == 0) {
		printf("%s: interface buffer read timeout\n", DEVNAME(sc));
		return ETIMEDOUT;
	}
	return 0;
}

/*
 * AQ2 firmware boot sequence.
 * Requests a firmware reboot, waits for it to complete, reads the
 * firmware version and interface version, and reads the filter
 * capabilities (ART base index) for packet classification setup.
 */
int
aq2_fw_reboot(struct aq_softc *sc)
{
	uint32_t v;
	int timo, err;
	char buf[32];
	uint32_t filter_caps[3];

	sc->sc_fw_ops = &aq2_fw_ops;
	sc->sc_features = FEATURES_AQ2;

	AQ_WRITE_REG(sc, AQ2_MCP_HOST_REQ_INT_CLR_REG, 1);
	AQ_WRITE_REG(sc, AQ2_MIF_BOOT_REG, 1);	/* reboot request */
	for (timo = 200000; timo > 0; timo--) {
		v = AQ_READ_REG(sc, AQ2_MIF_BOOT_REG);
		if ((v & AQ2_MIF_BOOT_BOOT_STARTED) && v != 0xffffffff)
			break;
		delay(10);
	}
	if (timo <= 0) {
		printf(": FW reboot timeout\n");
		return ETIMEDOUT;
	}

	for (timo = 2000000; timo > 0; timo--) {
		v = AQ_READ_REG(sc, AQ2_MIF_BOOT_REG);
		if ((v & AQ2_MIF_BOOT_FW_INIT_FAILED) ||
		    (v & AQ2_MIF_BOOT_FW_INIT_COMP_SUCCESS))
			break;
		v = AQ_READ_REG(sc, AQ2_MCP_HOST_REQ_INT_REG);
		if (v & AQ2_MCP_HOST_REQ_INT_READY)
			break;
		delay(10);
	}
	if (timo <= 0) {
		printf(": FW restart timeout\n");
		return ETIMEDOUT;
	}

	v = AQ_READ_REG(sc, AQ2_MIF_BOOT_REG);
	if (v & AQ2_MIF_BOOT_FW_INIT_FAILED) {
		printf(": FW restart failed\n");
		return ETIMEDOUT;
	}

	v = AQ_READ_REG(sc, AQ2_MCP_HOST_REQ_INT_REG);
	if (v & AQ2_MCP_HOST_REQ_INT_READY) {
		printf(": firmware required\n");
		return ENXIO;
	}

	/*
	 * Get aq2 firmware version.
	 * Note that the bit layout and its meaning are different from aq1.
	 */
	err = aq2_interface_buffer_read(sc, AQ2_FW_INTERFACE_OUT_VERSION_BUNDLE_REG,
	    (uint32_t *)&v, sizeof(v));
	if (err != 0)
		return err;

	sc->sc_fw_version =
	    (((v & AQ2_FW_INTERFACE_OUT_VERSION_MAJOR) >>
		AQ2_FW_INTERFACE_OUT_VERSION_MAJOR_S) << 24) |
	    (((v & AQ2_FW_INTERFACE_OUT_VERSION_MINOR) >>
		AQ2_FW_INTERFACE_OUT_VERSION_MINOR_S) << 16) |
	    (((v & AQ2_FW_INTERFACE_OUT_VERSION_BUILD) >>
		AQ2_FW_INTERFACE_OUT_VERSION_BUILD_S));

	err = aq2_interface_buffer_read(sc, AQ2_FW_INTERFACE_OUT_VERSION_IFACE_REG,
	    (uint32_t *)&v, sizeof(v));
	if (err != 0)
		return err;

	switch (v & AQ2_FW_INTERFACE_OUT_VERSION_IFACE_VER) {
	case AQ2_FW_INTERFACE_OUT_VERSION_IFACE_VER_A0:
		sc->sc_features |= FEATURES_AQ2_IFACE_A0;
		strncpy(buf, "A0", sizeof(buf));
		break;
	case AQ2_FW_INTERFACE_OUT_VERSION_IFACE_VER_B0:
		sc->sc_features |= FEATURES_AQ2_IFACE_B0;
		strncpy(buf, "B0", sizeof(buf));
		break;
	default:
		snprintf(buf, sizeof(buf), "(unknown 0x%08x)", v);
		break;
	}
	printf(", Atlantic2 %s, F/W version %d.%d.%d", buf,
	    FW_VERSION_MAJOR(sc), FW_VERSION_MINOR(sc), FW_VERSION_BUILD(sc));

	aq2_interface_buffer_read(sc, AQ2_FW_INTERFACE_OUT_FILTER_CAPS_REG,
	    filter_caps, sizeof(filter_caps));
	sc->sc_art_filter_base_index = ((filter_caps[2] &
	    AQ2_FW_INTERFACE_OUT_FILTER_CAPS3_RESOLVER_BASE_INDEX) >>
	    AQ2_FW_INTERFACE_OUT_FILTER_CAPS3_RESOLVER_BASE_INDEX_SHIFT) * 8;

	/* debug info */
	v = AQ_READ_REG(sc, AQ_HW_REVISION_REG);
	DPRINTF(("%s: HW Rev: 0x%08x\n", DEVNAME(sc), v));

	return 0;
}

/*
 * Reset the hardware interrupt controller, then call the firmware-
 * specific reset function (which reads capabilities / configures
 * the firmware interface).
 */
int
aq_hw_reset(struct aq_softc *sc)
{
	int error;

	/* disable irq */
	AQ_WRITE_REG_BIT(sc, AQ_INTR_CTRL_REG, AQ_INTR_CTRL_RESET_DIS, 0);

	/* apply */
	AQ_WRITE_REG_BIT(sc, AQ_INTR_CTRL_REG, AQ_INTR_CTRL_RESET_IRQ, 1);

	/* wait ack 10 times by 1ms */
	WAIT_FOR(
	    (AQ_READ_REG(sc, AQ_INTR_CTRL_REG) & AQ_INTR_CTRL_RESET_IRQ) == 0,
	    1000, 10, &error);
	if (error != 0) {
		printf(": IRQ reset failed: %d\n", error);
		return error;
	}

	return sc->sc_fw_ops->reset(sc);
}

/*
 * Read the MAC address from AQ1's eFuse shadow area via the firmware
 * mailbox.  The eFuse stores a factory-programmed MAC address.
 */
int
aq1_get_mac_addr(struct aq_softc *sc)
{
	uint32_t mac_addr[2];
	uint32_t efuse_shadow_addr;
	int err;

	efuse_shadow_addr = 0;
	if (FW_VERSION_MAJOR(sc) >= 2)
		efuse_shadow_addr = AQ_READ_REG(sc, FW2X_MPI_EFUSEADDR_REG);
	else
		efuse_shadow_addr = AQ_READ_REG(sc, FW1X_MPI_EFUSEADDR_REG);

	if (efuse_shadow_addr == 0) {
		printf(": cannot get efuse addr\n");
		return ENXIO;
	}

	DPRINTF(("%s: efuse_shadow_addr = %x\n", DEVNAME(sc), efuse_shadow_addr));

	memset(mac_addr, 0, sizeof(mac_addr));
	err = aq1_fw_downld_dwords(sc, efuse_shadow_addr + (40 * 4),
	    mac_addr, 2);
	if (err < 0)
		return err;

	if (mac_addr[0] == 0 && mac_addr[1] == 0) {
		printf(": mac address not found\n");
		return ENXIO;
	}

	DPRINTF(("%s: mac0 %x mac1 %x\n", DEVNAME(sc), mac_addr[0],
	    mac_addr[1]));

	mac_addr[0] = htobe32(mac_addr[0]);
	mac_addr[1] = htobe32(mac_addr[1]);

	DPRINTF(("%s: mac0 %x mac1 %x\n", DEVNAME(sc), mac_addr[0],
	    mac_addr[1]));

	memcpy(sc->sc_enaddr.ether_addr_octet,
	    (uint8_t *)mac_addr, ETHER_ADDR_LEN);

	return 0;
}

/*
 * Power management hook (suspend/resume).
 * Currently a no-op; the driver does not implement suspend/resume.
 */
int
aq_activate(struct device *self, int act)
{
	return 0;
}

/*
 * Read dwords from the AQ1 firmware's internal memory via the mailbox.
 * Acquires a semaphore for exclusive access, then issues a series of
 * mailbox read commands.  Used to read the MAC address, firmware
 * capabilities, and statistics from firmware memory.
 */
int
aq1_fw_downld_dwords(struct aq_softc *sc, uint32_t addr, uint32_t *p,
    uint32_t cnt)
{
	uint32_t v;
	int error = 0;

	WAIT_FOR(AQ_READ_REG(sc, AQ_FW_SEM_RAM_REG) == 1, 1, 10000, &error);
	if (error != 0) {
		AQ_WRITE_REG(sc, AQ_FW_SEM_RAM_REG, 1);
		v = AQ_READ_REG(sc, AQ_FW_SEM_RAM_REG);
		if (v == 0) {
			printf("%s: %s:%d: timeout\n",
			    DEVNAME(sc), __func__, __LINE__);
			return ETIMEDOUT;
		}
	}

	AQ_WRITE_REG(sc, AQ_FW_MBOX_ADDR_REG, addr);

	error = 0;
	for (; cnt > 0 && error == 0; cnt--) {
		/* execute mailbox interface */
		AQ_WRITE_REG_BIT(sc, AQ_FW_MBOX_CMD_REG,
		    AQ_FW_MBOX_CMD_EXECUTE, 1);
		if (sc->sc_features & FEATURES_AQ1_REV_B1) {
			WAIT_FOR(AQ_READ_REG(sc, AQ_FW_MBOX_ADDR_REG) != addr,
			    1, 1000, &error);
		} else {
			WAIT_FOR((AQ_READ_REG(sc, AQ_FW_MBOX_CMD_REG) &
			    AQ_FW_MBOX_CMD_BUSY) == 0,
			    1, 1000, &error);
		}
		*p++ = AQ_READ_REG(sc, AQ_FW_MBOX_VAL_REG);
		addr += sizeof(uint32_t);
	}
	AQ_WRITE_REG(sc, AQ_FW_SEM_RAM_REG, 1);

	if (error != 0)
		printf("%s: %s:%d: timeout\n",
		    DEVNAME(sc), __func__, __LINE__);

	return error;
}

/*
 * AQ1 fw2x reset: reads the firmware capabilities bitmask from the
 * mailbox.  The capabilities indicate which features (link speeds,
 * EEE, statistics, etc.) the firmware supports.
 */
int
aq_fw2x_reset(struct aq_softc *sc)
{
	struct aq_fw2x_capabilities caps = { 0 };
	int error;

	error = aq1_fw_downld_dwords(sc,
	    sc->sc_mbox_addr + offsetof(struct aq_fw2x_mailbox, caps),
	    (uint32_t *)&caps, sizeof caps / sizeof(uint32_t));
	if (error != 0) {
		printf("%s: fw2x> can't get F/W capabilities mask, error %d\n",
		    DEVNAME(sc), error);
		return error;
	}
	sc->sc_fw_caps = caps.caps_lo | ((uint64_t)caps.caps_hi << 32);

	DPRINTF(("%s: fw2x> F/W capabilities=0x%llx\n", DEVNAME(sc),
	    sc->sc_fw_caps));

	return 0;
}

int
aq_fw1x_reset(struct aq_softc *sc)
{
	printf("%s: unimplemented %s\n", DEVNAME(sc), __func__);
	return 0;
}

int
aq_fw1x_set_mode(struct aq_softc *sc, enum aq_hw_fw_mpi_state w,
    enum aq_link_speed x, enum aq_link_fc y, enum aq_link_eee z)
{
	return 0;
}

int
aq_fw1x_get_mode(struct aq_softc *sc, enum aq_hw_fw_mpi_state *w,
    enum aq_link_speed *x, enum aq_link_fc *y, enum aq_link_eee *z)
{
	return 0;
}

int
aq_fw1x_get_stats(struct aq_softc *sc, struct aq_hw_stats_s *w)
{
	return 0;
}


/*
 * Read current link state from fw2x.
 * The MPI state register contains the negotiated link speed and flow
 * control status, updated by firmware when link state changes.
 */
int
aq_fw2x_get_mode(struct aq_softc *sc, enum aq_hw_fw_mpi_state *modep,
    enum aq_link_speed *speedp, enum aq_link_fc *fcp, enum aq_link_eee *eeep)
{
	uint64_t mpi_state, mpi_ctrl;
	enum aq_link_speed speed;
	enum aq_link_fc fc;

	AQ_MPI_LOCK(sc);

	mpi_state = AQ_READ64_REG(sc, FW2X_MPI_STATE_REG);
	if (modep != NULL) {
		mpi_ctrl = AQ_READ64_REG(sc, FW2X_MPI_CONTROL_REG);
		if (mpi_ctrl & FW2X_CTRL_RATE_MASK)
			*modep = MPI_INIT;
		else
			*modep = MPI_DEINIT;
	}

	AQ_MPI_UNLOCK(sc);

	if (mpi_state & FW2X_CTRL_RATE_10G)
		speed = AQ_LINK_10G;
	else if (mpi_state & FW2X_CTRL_RATE_5G)
		speed = AQ_LINK_5G;
	else if (mpi_state & FW2X_CTRL_RATE_2G5)
		speed = AQ_LINK_2G5;
	else if (mpi_state & FW2X_CTRL_RATE_1G)
		speed = AQ_LINK_1G;
	else if (mpi_state & FW2X_CTRL_RATE_100M)
		speed = AQ_LINK_100M;
	else
		speed = AQ_LINK_NONE;
	if (speedp != NULL)
		*speedp = speed;

	fc = AQ_FC_NONE;
	if (mpi_state & FW2X_CTRL_PAUSE)
		fc |= AQ_FC_RX;
	if (mpi_state & FW2X_CTRL_ASYMMETRIC_PAUSE)
		fc |= AQ_FC_TX;
	if (fcp != NULL)
		*fcp = fc;

	if (eeep != NULL)
		*eeep = AQ_EEE_DISABLE;

	return 0;
}

int
aq_fw2x_get_stats(struct aq_softc *sc, struct aq_hw_stats_s *w)
{
	return 0;
}

/*
 * Wait for AQ2 firmware to acknowledge a shared memory write.
 * After writing configuration to the "interface in" region, the driver
 * signals the firmware and polls for the ACK to be cleared.
 */
static int
aq2_fw_wait_shared_ack(struct aq_softc *sc)
{
	int error;

	AQ_WRITE_REG(sc, AQ2_MIF_HOST_FINISHED_STATUS_WRITE_REG,
	    AQ2_MIF_HOST_FINISHED_STATUS_ACK);
	WAIT_FOR((AQ_READ_REG(sc, AQ2_MIF_HOST_FINISHED_STATUS_READ_REG) &
	    AQ2_MIF_HOST_FINISHED_STATUS_ACK) == 0, 100, 100000, &error);

	return error;
}

/*
 * AQ2 firmware reset: set link control to active mode, configure MTU,
 * set up multicast/broadcast/promisc receive policies, and wait for
 * firmware acknowledgment.
 */
int
aq2_fw_reset(struct aq_softc *sc)
{
	uint32_t v;
	int error;

	AQ_WRITE_REG_BIT(sc, AQ2_FW_INTERFACE_IN_LINK_CONTROL_REG,
	    AQ2_FW_INTERFACE_IN_LINK_CONTROL_MODE,
	    AQ2_FW_INTERFACE_IN_LINK_CONTROL_MODE_ACTIVE);

	AQ_WRITE_REG(sc, AQ2_FW_INTERFACE_IN_MTU_REG,
	    /*AQ2_JUMBO_MTU*/ MCLBYTES + sizeof(struct ether_header));

	v = AQ_READ_REG(sc, AQ2_FW_INTERFACE_IN_REQUEST_POLICY_REG);
	v |= AQ2_FW_INTERFACE_IN_REQUEST_POLICY_MCAST_QUEUE_OR_TC;
	v &= ~AQ2_FW_INTERFACE_IN_REQUEST_POLICY_MCAST_RX_QUEUE_TC_INDEX;
	v |= AQ2_FW_INTERFACE_IN_REQUEST_POLICY_MCAST_ACCEPT;
	v |= AQ2_FW_INTERFACE_IN_REQUEST_POLICY_BCAST_QUEUE_OR_TC;
	v &= AQ2_FW_INTERFACE_IN_REQUEST_POLICY_BCAST_RX_QUEUE_TC_INDEX;
	v |= AQ2_FW_INTERFACE_IN_REQUEST_POLICY_BCAST_ACCEPT;
	v |= AQ2_FW_INTERFACE_IN_REQUEST_POLICY_PROMISC_QUEUE_OR_TC;
	v &= ~AQ2_FW_INTERFACE_IN_REQUEST_POLICY_PROMISC_RX_QUEUE_TX_INDEX;
	AQ_WRITE_REG(sc, AQ2_FW_INTERFACE_IN_REQUEST_POLICY_REG, v);

	error = aq2_fw_wait_shared_ack(sc);
	if (error != 0)
		printf(": reset timed out\n");
	return error;
}

/*
 * Read MAC address for AQ2 devices.
 * Reads from the firmware interface "in" region.  Falls back to
 * reading from the device tree on FDT platforms (e.g. ARM).
 */
int
aq2_get_mac_addr(struct aq_softc *sc)
{
	uint32_t mac_addr[2];

	memset(mac_addr, 0, sizeof(mac_addr));
	AQ_READ_REGS(sc, AQ2_FW_INTERFACE_IN_MAC_ADDRESS_REG,
	    mac_addr, nitems(mac_addr));

#ifdef __HAVE_FDT
	if (mac_addr[0] == 0 && mac_addr[1] == 0 &&
	    PCITAG_NODE(sc->sc_pcitag)) {
		OF_getprop(PCITAG_NODE(sc->sc_pcitag), "local-mac-address",
		    mac_addr, ETHER_ADDR_LEN);
	}
#endif

	if (mac_addr[0] == 0 && mac_addr[1] == 0) {
		printf(": mac address not found\n");
		return ENXIO;
	}

	mac_addr[0] = htole32(mac_addr[0]);
	mac_addr[1] = htole32(mac_addr[1]);

	memcpy(sc->sc_enaddr.ether_addr_octet,
	    (uint8_t *)mac_addr, ETHER_ADDR_LEN);
	return 0;
}

/*
 * Configure link speed, flow control, and EEE on AQ2 firmware.
 * Writes the desired link options to the firmware shared memory
 * "interface in" region and waits for acknowledgment.
 */
int
aq2_fw_set_mode(struct aq_softc *sc, enum aq_hw_fw_mpi_state w,
    enum aq_link_speed speed, enum aq_link_fc fc, enum aq_link_eee eee)
{
	uint32_t v, ov;
	int error;

	AQ_MPI_LOCK(sc);

	v = AQ_READ_REG(sc, AQ2_FW_INTERFACE_IN_LINK_OPTIONS_REG);
	v &= ~(
	    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_10G |
	    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_N5G |
	    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_5G |
	    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_N2G5 |
	    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_2G5 |
	    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_1G |
	    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_100M |
	    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_10M |
	    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_1G_HD |
	    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_100M_HD |
	    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_10M_HD);

	v &= ~AQ2_FW_INTERFACE_IN_LINK_OPTIONS_LINK_UP;
	ov = v;

	if (speed & AQ_LINK_10G)
		v |= AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_10G;
	if (speed & AQ_LINK_5G)
		v |= AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_N5G |
		    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_5G;
	if (speed & AQ_LINK_2G5)
		v |= AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_N2G5 |
		    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_2G5;
	if (speed & AQ_LINK_1G)
		v |= AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_1G |
		    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_1G_HD;
	if (speed & AQ_LINK_100M)
		v |= AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_100M |
		    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_100M_HD;
	if (speed & AQ_LINK_10M) {
		v |= AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_10M |
		    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_RATE_10M_HD;
	}

	/* flow control */
	v &= ~(AQ2_FW_INTERFACE_IN_LINK_OPTIONS_PAUSE_TX |
	    AQ2_FW_INTERFACE_IN_LINK_OPTIONS_PAUSE_RX);
	if (fc & AQ_FC_TX)
		v |= AQ2_FW_INTERFACE_IN_LINK_OPTIONS_PAUSE_TX;
	if (fc & AQ_FC_RX)
		v |= AQ2_FW_INTERFACE_IN_LINK_OPTIONS_PAUSE_RX;

	if (speed == AQ_LINK_NONE) {
		AQ_WRITE_REG_BIT(sc, AQ2_FW_INTERFACE_IN_LINK_CONTROL_REG,
		    AQ2_FW_INTERFACE_IN_LINK_CONTROL_MODE,
		    AQ2_FW_INTERFACE_IN_LINK_CONTROL_MODE_SHUTDOWN);
	} else {
		AQ_WRITE_REG_BIT(sc, AQ2_FW_INTERFACE_IN_LINK_CONTROL_REG,
		    AQ2_FW_INTERFACE_IN_LINK_CONTROL_MODE,
		    AQ2_FW_INTERFACE_IN_LINK_CONTROL_MODE_ACTIVE);
		v |= AQ2_FW_INTERFACE_IN_LINK_OPTIONS_LINK_UP;
	}

	AQ_WRITE_REG(sc, AQ2_FW_INTERFACE_IN_LINK_OPTIONS_REG, v);
	error = aq2_fw_wait_shared_ack(sc);

	AQ_MPI_UNLOCK(sc);
	return error;
}

/*
 * Read current link state from AQ2 firmware.
 * Reads the link status register from the "interface out" shared memory
 * and decodes the negotiated speed, flow control, and EEE state.
 */
int
aq2_fw_get_mode(struct aq_softc *sc, enum aq_hw_fw_mpi_state *modep,
    enum aq_link_speed *speedp, enum aq_link_fc *fcp, enum aq_link_eee *eeep)
{
	uint32_t v;
	enum aq_link_speed speed;
	enum aq_link_fc fc = 0;
	enum aq_link_eee eee;

	if (modep != NULL)
		*modep = MPI_INIT;

	v = AQ_READ_REG(sc, AQ2_FW_INTERFACE_OUT_LINK_STATUS_REG);
	switch ((v & AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE) >>
	    AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE_S) {
	case AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE_10G:
		speed = AQ_LINK_10G;
		break;
	case AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE_5G:
		speed = AQ_LINK_5G;
		break;
	case AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE_2G5:
		speed = AQ_LINK_2G5;
		break;
	case AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE_1G:
		speed = AQ_LINK_1G;
		break;
	case AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE_100M:
		speed = AQ_LINK_100M;
		break;
	case AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE_10M:
		speed = AQ_LINK_10M;
		break;
	case AQ2_FW_INTERFACE_OUT_LINK_STATUS_RATE_INVALID:
	default:
		speed = AQ_LINK_NONE;
		break;
	}
	if (speedp != NULL)
		*speedp = speed;

	if (v & AQ2_FW_INTERFACE_OUT_LINK_STATUS_PAUSE_TX)
		fc |= AQ_FC_TX;
	if (v & AQ2_FW_INTERFACE_OUT_LINK_STATUS_PAUSE_RX)
		fc |= AQ_FC_RX;
	if (fcp != NULL)
		*fcp = fc;

	eee = (v & AQ2_FW_INTERFACE_OUT_LINK_STATUS_EEE) ?
	    AQ_EEE_ENABLE : AQ_EEE_DISABLE;
	if (eeep != NULL)
		*eeep = eee;

	return 0;
}

int
aq2_fw_get_stats(struct aq_softc *sc, struct aq_hw_stats_s *w)
{
	return 0;
}

/*
 * Main hardware initialization.
 * Called once during attach after firmware is booted.  Configures:
 *   - PCI DMA request limits (AQ1 B0 workaround)
 *   - FPGA clock ratio (AQ2)
 *   - TX and RX data paths
 *   - Primary MAC address filter
 *   - QoS (traffic class buffer sizes, scheduling weights)
 *   - AQ2 action resolver table
 *   - Interrupt controller mode (MSI-X/MSI/legacy)
 *   - Link status interrupt mapping
 */
int
aq_hw_init(struct aq_softc *sc, int irqmode, int multivec)
{
	uint32_t v;

	if (HWTYPE_AQ1_P(sc)) {
		/* Force limit MRRS on RDM/TDM to 2K */
		v = AQ_READ_REG(sc, AQ_PCI_REG_CONTROL_6_REG);
		AQ_WRITE_REG(sc, AQ_PCI_REG_CONTROL_6_REG,
		    (v & ~0x0707) | 0x0404);

		/*
		 * TX DMA total request limit. B0 hardware is not capable to
		 * handle more than (8K-MRRS) incoming DMA data.
		 * Value 24 in 256byte units
		 */
		AQ_WRITE_REG(sc, AQ_HW_TX_DMA_TOTAL_REQ_LIMIT_REG, 24);
	}

	if (HWTYPE_AQ2_P(sc)) {
		uint32_t fpgaver, speed;
		fpgaver = AQ_READ_REG(sc, AQ2_HW_FPGA_VERSION_REG);
		if (fpgaver < 0x01000000)
			speed = AQ2_LAUNCHTIME_CTRL_RATIO_SPEED_FULL;
		else if (fpgaver >= 0x01008502)
			speed = AQ2_LAUNCHTIME_CTRL_RATIO_SPEED_HALF;
		else
			speed = AQ2_LAUNCHTIME_CTRL_RATIO_SPEED_QUARTER;
		AQ_WRITE_REG_BIT(sc, AQ2_LAUNCHTIME_CTRL_REG,
		    AQ2_LAUNCHTIME_CTRL_RATIO, speed);
	}

	aq_hw_init_tx_path(sc);
	aq_hw_init_rx_path(sc);

	if (aq_set_mac_addr(sc, AQ_HW_MAC_OWN, sc->sc_enaddr.ether_addr_octet))
		return EINVAL;

	aq_set_linkmode(sc, AQ_LINK_NONE, AQ_FC_NONE, AQ_EEE_DISABLE);

	aq_hw_qos_set(sc);

	if (HWTYPE_AQ2_P(sc)) {
		AQ_WRITE_REG_BIT(sc, AQ2_RPF_NEW_CTRL_REG,
		    AQ2_RPF_NEW_CTRL_ENABLE, 1);
	}

	/* Enable interrupt */
	AQ_WRITE_REG(sc, AQ_INTR_CTRL_REG, AQ_INTR_CTRL_RESET_DIS);
	AQ_WRITE_REG_BIT(sc, AQ_INTR_CTRL_REG, AQ_INTR_CTRL_MULTIVEC, multivec);

	AQ_WRITE_REG_BIT(sc, AQ_INTR_CTRL_REG, AQ_INTR_CTRL_IRQMODE, irqmode);

	AQ_WRITE_REG(sc, AQ_INTR_AUTOMASK_REG, 0xffffffff);

	AQ_WRITE_REG(sc, AQ_GEN_INTR_MAP_REG(0),
	    ((AQ_B0_ERR_INT << 24) | (1U << 31)) |
	    ((AQ_B0_ERR_INT << 16) | (1 << 23))
	);

	/* link interrupt */
	AQ_WRITE_REG(sc, AQ_GEN_INTR_MAP_REG(3),
	    (1 << 7) | sc->sc_linkstat_irq);

	return 0;
}

/*
 * Initialize the transmit data path.
 * Configures the TX traffic class mode, LSO (Large Send Offload)
 * TCP flag templates for segmentation, TPO2 offload engine,
 * DCA (Direct Cache Access, disabled), and scratch pad insertion.
 */
void
aq_hw_init_tx_path(struct aq_softc *sc)
{
	/* Tx TC/RSS number config */
	AQ_WRITE_REG_BIT(sc, TPB_TX_BUF_REG, TPB_TX_BUF_TC_MODE_EN, 1);

	AQ_WRITE_REG_BIT(sc, THM_LSO_TCP_FLAG1_REG,
	    THM_LSO_TCP_FLAG1_FIRST, 0x0ff6);
	AQ_WRITE_REG_BIT(sc, THM_LSO_TCP_FLAG1_REG,
	    THM_LSO_TCP_FLAG1_MID,   0x0ff6);
	AQ_WRITE_REG_BIT(sc, THM_LSO_TCP_FLAG2_REG,
	   THM_LSO_TCP_FLAG2_LAST,  0x0f7f);

	/* misc */
	AQ_WRITE_REG(sc, TX_TPO2_REG,
	   (sc->sc_features & FEATURES_TPO2) ? TX_TPO2_EN : 0);
	AQ_WRITE_REG_BIT(sc, TDM_DCA_REG, TDM_DCA_EN, 0);
	AQ_WRITE_REG_BIT(sc, TDM_DCA_REG, TDM_DCA_MODE, 0);

	AQ_WRITE_REG_BIT(sc, TPB_TX_BUF_REG, TPB_TX_BUF_SCP_INS_EN, 1);

	if ((sc->sc_features & FEATURES_AQ1_REV_B) || HWTYPE_AQ2_P(sc)) {
		AQ_WRITE_REG_BIT(sc, TPB_TX_BUF_REG, TPB_TX_BUF_CLK_GATE_EN, 0);
	}
}

/*
 * Initialize the receive data path.
 * Configures:
 *   - RX traffic class and flow control mode
 *   - RSS hash type selection (AQ2: all hash types; AQ1: via RPF2)
 *   - RSS control register with queue count encoding
 *   - Ethertype filters (AQ1: disable all 32 entries)
 *   - L2 unicast/multicast address filters (disable, set to HOST action)
 *   - VLAN filters (promiscuous, accept untagged)
 *   - AQ2 Action Resolver Table entries for L2/VLAN filtering
 *   - Broadcast filter (enable, deliver to host)
 *   - DCA (disabled)
 */
void
aq_hw_init_rx_path(struct aq_softc *sc)
{
	int i;

	/* clear setting */
	AQ_WRITE_REG_BIT(sc, RPB_RPF_RX_REG, RPB_RPF_RX_TC_MODE, 0);
	AQ_WRITE_REG_BIT(sc, RPB_RPF_RX_REG, RPB_RPF_RX_FC_MODE, 0);

	if (HWTYPE_AQ2_P(sc)) {
		AQ_WRITE_REG_BIT(sc, AQ2_RPF_REDIR2_REG,
		    AQ2_RPF_REDIR2_HASHTYPE, AQ2_RPF_REDIR2_HASHTYPE_ALL);
	}

	if (sc->sc_nqueues > 1) {
		uint32_t bits;

		AQ_WRITE_REG_BIT(sc, RPB_RPF_RX_REG, RPB_RPF_RX_TC_MODE, 1);
		AQ_WRITE_REG_BIT(sc, RPB_RPF_RX_REG, RPB_RPF_RX_FC_MODE, 1);

		switch (sc->sc_nqueues) {
		case 2:
			bits = 0x11111111;
			break;
		case 4:
			bits = 0x22222222;
			break;
		case 8:
			bits = 0x33333333;
			break;
		}

		AQ_WRITE_REG(sc, RX_FLR_RSS_CONTROL1_REG,
		    RX_FLR_RSS_CONTROL1_EN | bits);
	} else {
		AQ_WRITE_REG(sc, RX_FLR_RSS_CONTROL1_REG, 0);
	}

	if (HWTYPE_AQ1_P(sc)) {
		for (i = 0; i < 32; i++) {
			AQ_WRITE_REG_BIT(sc, RPF_ETHERTYPE_FILTER_REG(i),
			   RPF_ETHERTYPE_FILTER_EN, 0);
		}
	}

	/* L2 and Multicast filters */
	for (i = 0; i < AQ_HW_MAC_NUM; i++) {
		AQ_WRITE_REG_BIT(sc, RPF_L2UC_MSW_REG(i), RPF_L2UC_MSW_EN, 0);
		AQ_WRITE_REG_BIT(sc, RPF_L2UC_MSW_REG(i), RPF_L2UC_MSW_ACTION,
		    RPF_ACTION_HOST);
	}
	AQ_WRITE_REG(sc, RPF_MCAST_FILTER_MASK_REG, 0);
	AQ_WRITE_REG(sc, RPF_MCAST_FILTER_REG(0), 0x00010fff);

	/* Vlan filters */
	AQ_WRITE_REG_BIT(sc, RPF_VLAN_TPID_REG, RPF_VLAN_TPID_OUTER,
	    ETHERTYPE_QINQ);
	AQ_WRITE_REG_BIT(sc, RPF_VLAN_TPID_REG, RPF_VLAN_TPID_INNER,
	    ETHERTYPE_VLAN);
	AQ_WRITE_REG_BIT(sc, RPF_VLAN_MODE_REG, RPF_VLAN_MODE_PROMISC, 1);

	if ((sc->sc_features & FEATURES_AQ1_REV_B) || HWTYPE_AQ2_P(sc)) {
		AQ_WRITE_REG_BIT(sc, RPF_VLAN_MODE_REG,
		    RPF_VLAN_MODE_ACCEPT_UNTAGGED, 1);
		AQ_WRITE_REG_BIT(sc, RPF_VLAN_MODE_REG,
		    RPF_VLAN_MODE_UNTAGGED_ACTION, RPF_ACTION_HOST);
	}

	if (HWTYPE_AQ2_P(sc)) {
		AQ_WRITE_REG_BIT(sc, AQ2_RPF_REC_TAB_ENABLE_REG,
		    AQ2_RPF_REC_TAB_ENABLE_MASK, 0xffff);
		AQ_WRITE_REG_BIT(sc, RPF_L2UC_MSW_REG(0),
		    RPF_L2UC_MSW_TAG, 1);
		AQ_WRITE_REG_BIT(sc, AQ2_RPF_L2BC_TAG_REG,
		    AQ2_RPF_L2BC_TAG_MASK, 1);

		aq2_filter_art_set(sc, AQ2_RPF_INDEX_L2_PROMISC_OFF,
		    0, AQ2_RPF_TAG_UC_MASK | AQ2_RPF_TAG_ALLMC_MASK,
		    AQ2_ART_ACTION_DROP);
		aq2_filter_art_set(sc, AQ2_RPF_INDEX_VLAN_PROMISC_OFF,
		    0, AQ2_RPF_TAG_VLAN_MASK | AQ2_RPF_TAG_UNTAG_MASK,
		    AQ2_ART_ACTION_DROP);

		for (i = 0; i < 8; i++) {
			aq2_filter_art_set(sc, AQ2_RPF_INDEX_PCP_TO_TC + i,
			    (i << AQ2_RPF_TAG_PCP_SHIFT), AQ2_RPF_TAG_PCP_MASK,
			    AQ2_ART_ACTION_ASSIGN_TC(i % sc->sc_nqueues));
		}

	} else if (HWTYPE_AQ1_P(sc)) {
		if (sc->sc_features & FEATURES_RPF2)
			AQ_WRITE_REG(sc, RX_TCP_RSS_HASH_REG,
			    RX_TCP_RSS_HASH_RPF2);
		else
			AQ_WRITE_REG(sc, RX_TCP_RSS_HASH_REG, 0);

		/* we might want to figure out what this magic number does */
		AQ_WRITE_REG_BIT(sc, RX_TCP_RSS_HASH_REG,
		    RX_TCP_RSS_HASH_TYPE, 0x001e);
	}

	AQ_WRITE_REG_BIT(sc, RPF_L2BC_REG, RPF_L2BC_EN, 1);
	AQ_WRITE_REG_BIT(sc, RPF_L2BC_REG, RPF_L2BC_ACTION, RPF_ACTION_HOST);
	AQ_WRITE_REG_BIT(sc, RPF_L2BC_REG, RPF_L2BC_THRESHOLD, 0xffff);

	AQ_WRITE_REG_BIT(sc, RX_DMA_DCA_REG, RX_DMA_DCA_EN, 0);
	AQ_WRITE_REG_BIT(sc, RX_DMA_DCA_REG, RX_DMA_DCA_MODE, 0);
}

/*
 * Program a unicast MAC address into the hardware L2 filter.
 * Index 0 is reserved for the interface's own MAC address.
 * Indices 1..AQ_HW_MAC_NUM-1 are used for additional unicast
 * and multicast addresses.  Passing enaddr==NULL disables the entry.
 */
int
aq_set_mac_addr(struct aq_softc *sc, int index, uint8_t *enaddr)
{
	uint32_t h, l;

	if (index >= AQ_HW_MAC_NUM)
		return EINVAL;

	if (enaddr == NULL) {
		/* disable */
		AQ_WRITE_REG_BIT(sc,
		    RPF_L2UC_MSW_REG(index), RPF_L2UC_MSW_EN, 0);
		return 0;
	}

	h = (enaddr[0] <<  8) | (enaddr[1]);
	l = ((uint32_t)enaddr[2] << 24) | (enaddr[3] << 16) |
	    (enaddr[4] <<  8) | (enaddr[5]);

	/* disable, set, and enable */
	AQ_WRITE_REG_BIT(sc, RPF_L2UC_MSW_REG(index), RPF_L2UC_MSW_EN, 0);
	AQ_WRITE_REG(sc, RPF_L2UC_LSW_REG(index), l);
	AQ_WRITE_REG_BIT(sc, RPF_L2UC_MSW_REG(index),
	    RPF_L2UC_MSW_MACADDR_HI, h);
	AQ_WRITE_REG_BIT(sc, RPF_L2UC_MSW_REG(index),
	    RPF_L2UC_MSW_ACTION, RPF_ACTION_HOST);
	if (HWTYPE_AQ2_P(sc))
		AQ_WRITE_REG_BIT(sc, RPF_L2UC_MSW_REG(index),
		    RPF_L2UC_MSW_TAG, 1);
	AQ_WRITE_REG_BIT(sc, RPF_L2UC_MSW_REG(index), RPF_L2UC_MSW_EN, 1);

	return 0;
}

/* Query current link speed/fc/eee from firmware; fail if not initialized. */
int
aq_get_linkmode(struct aq_softc *sc, enum aq_link_speed *speed,
    enum aq_link_fc *fc, enum aq_link_eee *eee)
{
	enum aq_hw_fw_mpi_state mode;
	int error;

	error = sc->sc_fw_ops->get_mode(sc, &mode, speed, fc, eee);
	if (error != 0)
		return error;
	if (mode != MPI_INIT)
		return ENXIO;

	return 0;
}

/* Set desired link speed/fc/eee via firmware. */
int
aq_set_linkmode(struct aq_softc *sc, enum aq_link_speed speed,
    enum aq_link_fc fc, enum aq_link_eee eee)
{
	return sc->sc_fw_ops->set_mode(sc, MPI_INIT, speed, fc, eee);
}

/*
 * Set link parameters via fw2x MPI control register.
 * Builds a 64-bit control word with the desired link speeds, EEE,
 * and flow control settings, then writes it to the firmware.
 * MPI_INIT enables the link; MPI_DEINIT tears it down.
 */
int
aq_fw2x_set_mode(struct aq_softc *sc, enum aq_hw_fw_mpi_state mode,
    enum aq_link_speed speed, enum aq_link_fc fc, enum aq_link_eee eee)
{
	uint64_t mpi_ctrl;
	int error = 0;

	AQ_MPI_LOCK(sc);

	mpi_ctrl = AQ_READ64_REG(sc, FW2X_MPI_CONTROL_REG);

	switch (mode) {
	case MPI_INIT:
		mpi_ctrl &= ~FW2X_CTRL_RATE_MASK;
		if (speed & AQ_LINK_10G)
			mpi_ctrl |= FW2X_CTRL_RATE_10G;
		if (speed & AQ_LINK_5G)
			mpi_ctrl |= FW2X_CTRL_RATE_5G;
		if (speed & AQ_LINK_2G5)
			mpi_ctrl |= FW2X_CTRL_RATE_2G5;
		if (speed & AQ_LINK_1G)
			mpi_ctrl |= FW2X_CTRL_RATE_1G;
		if (speed & AQ_LINK_100M)
			mpi_ctrl |= FW2X_CTRL_RATE_100M;

		mpi_ctrl &= ~FW2X_CTRL_LINK_DROP;

		mpi_ctrl &= ~FW2X_CTRL_EEE_MASK;
		if (eee == AQ_EEE_ENABLE)
			mpi_ctrl |= FW2X_CTRL_EEE_MASK;

		mpi_ctrl &= ~(FW2X_CTRL_PAUSE | FW2X_CTRL_ASYMMETRIC_PAUSE);
		if (fc & AQ_FC_RX)
			mpi_ctrl |= FW2X_CTRL_PAUSE;
		if (fc & AQ_FC_TX)
			mpi_ctrl |= FW2X_CTRL_ASYMMETRIC_PAUSE;
		break;
	case MPI_DEINIT:
		mpi_ctrl &= ~(FW2X_CTRL_RATE_MASK | FW2X_CTRL_EEE_MASK);
		mpi_ctrl &= ~(FW2X_CTRL_PAUSE | FW2X_CTRL_ASYMMETRIC_PAUSE);
		break;
	default:
		printf("%s: fw2x> unknown MPI state %d\n", DEVNAME(sc), mode);
		error =  EINVAL;
		goto failure;
	}
	AQ_WRITE64_REG(sc, FW2X_MPI_CONTROL_REG, mpi_ctrl);

 failure:
	AQ_MPI_UNLOCK(sc);
	return error;
}

/*
 * Configure Quality of Service parameters.
 * Sets up the TX Packet Scheduler (TPS) with descriptor rate limits,
 * arbitration modes, and traffic class credit/weight values.
 * Configures TX and RX buffer sizes and high/low watermarks for
 * flow control (XOFF thresholds).
 * Maps 802.1p priority values to traffic classes.
 * For AQ2, also sets up ring-to-TC mapping tables.
 */
void
aq_hw_qos_set(struct aq_softc *sc)
{
	uint32_t tc = 0;
	uint32_t buff_size;

	/* TPS Descriptor rate init */
	AQ_WRITE_REG_BIT(sc, TPS_DESC_RATE_REG, TPS_DESC_RATE_TA_RST, 0);
	AQ_WRITE_REG_BIT(sc, TPS_DESC_RATE_REG, TPS_DESC_RATE_LIM, 0xa);

	/* TPS VM init */
	AQ_WRITE_REG_BIT(sc, TPS_DESC_VM_ARB_MODE_REG, TPS_DESC_VM_ARB_MODE, 0);

	/* TPS TC credits init */
	AQ_WRITE_REG_BIT(sc, TPS_DESC_TC_ARB_MODE_REG, TPS_DESC_TC_ARB_MODE, 0);
	AQ_WRITE_REG_BIT(sc, TPS_DATA_TC_ARB_MODE_REG, TPS_DATA_TC_ARB_MODE, 0);

	if (HWTYPE_AQ2_P(sc)) {
		AQ_WRITE_REG_BIT(sc, TPS_DATA_TCT_REG(tc),
		    TPS2_DATA_TCT_CREDIT_MAX, 0xfff0);
		AQ_WRITE_REG_BIT(sc, TPS_DATA_TCT_REG(tc),
		    TPS2_DATA_TCT_WEIGHT, 0x640);
	} else {
		AQ_WRITE_REG_BIT(sc, TPS_DATA_TCT_REG(tc),
		    TPS_DATA_TCT_CREDIT_MAX, 0xfff);
		AQ_WRITE_REG_BIT(sc, TPS_DATA_TCT_REG(tc),
		    TPS_DATA_TCT_WEIGHT, 0x64);
	}
	AQ_WRITE_REG_BIT(sc, TPS_DESC_TCT_REG(tc),
	    TPS_DESC_TCT_CREDIT_MAX, 0x50);
	AQ_WRITE_REG_BIT(sc, TPS_DESC_TCT_REG(tc),
	    TPS_DESC_TCT_WEIGHT, 0x1e);

	/* Tx buf size */
	tc = 0;
	buff_size = HWTYPE_AQ2_P(sc) ? AQ2_HW_TXBUF_MAX : AQ_HW_TXBUF_MAX;
	AQ_WRITE_REG_BIT(sc, TPB_TXB_BUFSIZE_REG(tc), TPB_TXB_BUFSIZE,
	    buff_size);
	AQ_WRITE_REG_BIT(sc, TPB_TXB_THRESH_REG(tc), TPB_TXB_THRESH_HI,
	    (buff_size * (1024 / 32) * 66) / 100);
	AQ_WRITE_REG_BIT(sc, TPB_TXB_THRESH_REG(tc), TPB_TXB_THRESH_LO,
	    (buff_size * (1024 / 32) * 50) / 100);

	/* QoS Rx buf size per TC */
	tc = 0;
	buff_size = HWTYPE_AQ2_P(sc) ? AQ2_HW_RXBUF_MAX : AQ_HW_RXBUF_MAX;
	AQ_WRITE_REG_BIT(sc, RPB_RXB_BUFSIZE_REG(tc), RPB_RXB_BUFSIZE,
	    buff_size);
	AQ_WRITE_REG_BIT(sc, RPB_RXB_XOFF_REG(tc), RPB_RXB_XOFF_EN, 0);
	AQ_WRITE_REG_BIT(sc, RPB_RXB_XOFF_REG(tc), RPB_RXB_XOFF_THRESH_HI,
	    (buff_size * (1024 / 32) * 66) / 100);
	AQ_WRITE_REG_BIT(sc, RPB_RXB_XOFF_REG(tc), RPB_RXB_XOFF_THRESH_LO,
	    (buff_size * (1024 / 32) * 50) / 100);

	/* QoS 802.1p priority -> TC mapping */
	int i_priority;
	for (i_priority = 0; i_priority < 8; i_priority++) {
		AQ_WRITE_REG_BIT(sc, RPF_RPB_RX_TC_UPT_REG,
		    RPF_RPB_RX_TC_UPT_MASK(i_priority), 0);
	}

	/* ring to TC mapping */
	if (HWTYPE_AQ2_P(sc)) {
		AQ_WRITE_REG_BIT(sc, TPB_TX_BUF_REG,
		    TPB_TX_BUF_TC_Q_RAND_MAP_EN, 1);

		AQ_WRITE_REG(sc, AQ2_TX_Q_TC_MAP_REG(0), 0x00000000);
		AQ_WRITE_REG(sc, AQ2_TX_Q_TC_MAP_REG(1), 0x00000000);
		AQ_WRITE_REG(sc, AQ2_TX_Q_TC_MAP_REG(2), 0x01010101);
		AQ_WRITE_REG(sc, AQ2_TX_Q_TC_MAP_REG(3), 0x01010101);
		AQ_WRITE_REG(sc, AQ2_TX_Q_TC_MAP_REG(4), 0x02020202);
		AQ_WRITE_REG(sc, AQ2_TX_Q_TC_MAP_REG(5), 0x02020202);
		AQ_WRITE_REG(sc, AQ2_TX_Q_TC_MAP_REG(6), 0x03030303);
		AQ_WRITE_REG(sc, AQ2_TX_Q_TC_MAP_REG(7), 0x03030303);

		AQ_WRITE_REG(sc, AQ2_RX_Q_TC_MAP_REG(0), 0x00000000);
		AQ_WRITE_REG(sc, AQ2_RX_Q_TC_MAP_REG(1), 0x11111111);
		AQ_WRITE_REG(sc, AQ2_RX_Q_TC_MAP_REG(2), 0x22222222);
		AQ_WRITE_REG(sc, AQ2_RX_Q_TC_MAP_REG(3), 0x33333333);
	}
}

/*
 * Initialize Receive Side Scaling (RSS).
 * RSS distributes incoming packets across multiple RX queues based on
 * a hash of the packet headers, enabling parallel processing on
 * multiple CPUs.
 *
 * Programs:
 *   1. AQ2 redirection table (64 entries per traffic class)
 *   2. The RSS hash key (Toeplitz hash, 40 bytes) - generated by
 *      stoeplitz_to_key() to match the kernel's software Toeplitz
 *   3. The RSS indirection table (maps hash values -> queue numbers)
 *      Entries are 3-bit queue IDs packed into 16-bit registers.
 */
int
aq_init_rss(struct aq_softc *sc)
{
	uint32_t rss_key[AQ_RSS_KEYSIZE / sizeof(uint32_t)];
	uint32_t redir;
	int bits, queue;
	int error;
	int i;

	if (sc->sc_nqueues == 1)
		return 0;

	if (HWTYPE_AQ2_P(sc)) {
		AQ_WRITE_REG_BIT(sc, AQ2_RPF_REDIR2_REG, AQ2_RPF_REDIR2_INDEX, 0);
		for (i = 0; i < AQ2_RPF_RSS_REDIR_MAX; i++) {
			int tc;
			int q;
			for (tc = 0; tc < 4; tc++) {
				q = (tc * 8) + (i % sc->sc_nqueues);
				AQ_WRITE_REG_BIT(sc, AQ2_RPF_RSS_REDIR_REG(tc, i),
				    AQ2_RPF_RSS_REDIR_TC_MASK(tc), q);
			}
		}
	}

	/* rss key is composed of 32 bit registers */
	stoeplitz_to_key(rss_key, sizeof(rss_key));
	for (i = 0; i < nitems(rss_key); i++) {
		AQ_WRITE_REG(sc, RPF_RSS_KEY_WR_DATA_REG, htobe32(rss_key[i]));
		AQ_WRITE_REG_BIT(sc, RPF_RSS_KEY_ADDR_REG, RPF_RSS_KEY_ADDR,
		    nitems(rss_key) - 1 - i);
		AQ_WRITE_REG_BIT(sc, RPF_RSS_KEY_ADDR_REG, RPF_RSS_KEY_WR_EN,
		    1);
		WAIT_FOR((AQ_READ_REG(sc, RPF_RSS_KEY_ADDR_REG) &
		    RPF_RSS_KEY_WR_EN) == 0, 1000, 10, &error);
		if (error != 0) {
			printf(": timed out setting rss key\n");
			return error;
		}
	}

	/*
	 * the redirection table has 64 entries, each entry is a 3 bit
	 * queue number, packed into a 16 bit register, so there are 12
	 * registers to program.
	 */
	bits = 0;
	redir = 0;
	queue = 0;
	for (i = 0; i < AQ_RSS_REDIR_ENTRIES; i++) {
		while (bits < 16) {
			redir |= (queue << bits);
			bits += 3;
			queue++;
			if (queue == sc->sc_nqueues)
				queue = 0;
		}

		AQ_WRITE_REG(sc, RPF_RSS_REDIR_WR_DATA_REG, htole16(redir));
		AQ_WRITE_REG_BIT(sc, RPF_RSS_REDIR_ADDR_REG, RPF_RSS_REDIR_ADDR,
		    i);
		AQ_WRITE_REG_BIT(sc, RPF_RSS_REDIR_ADDR_REG,
		    RPF_RSS_REDIR_WR_EN, 1);
		WAIT_FOR((AQ_READ_REG(sc, RPF_RSS_REDIR_ADDR_REG) &
		    RPF_RSS_REDIR_WR_EN) == 0, 1000, 10, &error);
		if (error != 0) {
			printf(": timed out setting rss table\n");
			return error;
		}
		redir >>= 16;
		bits -= 16;
	}

	return 0;
}

/*
 * Reset/initialize a TX descriptor ring.
 * If start==0, just disables the ring (used during teardown).
 * If start==1, programs the ring base address, size, head/tail pointers,
 * and interrupt mapping into the hardware, then enables the ring.
 */
void
aq_txring_reset(struct aq_softc *sc, struct aq_txring *tx, int start)
{
	daddr_t paddr;

	tx->tx_prod = 0;
	tx->tx_cons = 0;

	/* empty slots? */

	AQ_WRITE_REG_BIT(sc, TX_DMA_DESC_REG(tx->tx_q), TX_DMA_DESC_EN, 0);

	if (start == 0)
		return;

	paddr = AQ_DMA_DVA(&tx->tx_mem);
	AQ_WRITE_REG(sc, TX_DMA_DESC_BASE_ADDRLSW_REG(tx->tx_q), paddr);
	AQ_WRITE_REG(sc, TX_DMA_DESC_BASE_ADDRMSW_REG(tx->tx_q),
	    paddr >> 32);

	AQ_WRITE_REG_BIT(sc, TX_DMA_DESC_REG(tx->tx_q), TX_DMA_DESC_LEN,
	    AQ_TXD_NUM / 8);

	tx->tx_prod = AQ_READ_REG(sc, TX_DMA_DESC_TAIL_PTR_REG(tx->tx_q));
	tx->tx_cons = tx->tx_prod;
	AQ_WRITE_REG(sc, TX_DMA_DESC_WRWB_THRESH_REG(tx->tx_q), 0);

	AQ_WRITE_REG_BIT(sc, AQ_INTR_IRQ_MAP_TX_REG(tx->tx_q),
	    AQ_INTR_IRQ_MAP_TX_IRQMAP(tx->tx_q), tx->tx_irq);
	AQ_WRITE_REG_BIT(sc, AQ_INTR_IRQ_MAP_TX_REG(tx->tx_q),
	    AQ_INTR_IRQ_MAP_TX_EN(tx->tx_q), 1);

	AQ_WRITE_REG_BIT(sc, TX_DMA_DESC_REG(tx->tx_q), TX_DMA_DESC_EN, 1);

	AQ_WRITE_REG_BIT(sc, TDM_DCAD_REG(tx->tx_q), TDM_DCAD_CPUID, 0);
	AQ_WRITE_REG_BIT(sc, TDM_DCAD_REG(tx->tx_q), TDM_DCAD_CPUID_EN, 0);
}

/*
 * Reset/initialize an RX descriptor ring.
 * If start==0, just disables the ring.
 * If start==1, programs ring base address, size, buffer size,
 * VLAN stripping mode, head/tail pointers, interrupt mapping,
 * and DCA settings, then enables the ring.
 */
void
aq_rxring_reset(struct aq_softc *sc, struct aq_rxring *rx, int start)
{
	daddr_t paddr;
	int strip;

	AQ_WRITE_REG_BIT(sc, RX_DMA_DESC_REG(rx->rx_q), RX_DMA_DESC_EN, 0);
	/* drain */

	if (start == 0)
		return;

	paddr = AQ_DMA_DVA(&rx->rx_mem);
	AQ_WRITE_REG(sc, RX_DMA_DESC_BASE_ADDRLSW_REG(rx->rx_q), paddr);
	AQ_WRITE_REG(sc, RX_DMA_DESC_BASE_ADDRMSW_REG(rx->rx_q),
	    paddr >> 32);

	AQ_WRITE_REG_BIT(sc, RX_DMA_DESC_REG(rx->rx_q), RX_DMA_DESC_LEN,
	    AQ_RXD_NUM / 8);

	AQ_WRITE_REG_BIT(sc, RX_DMA_DESC_BUFSIZE_REG(rx->rx_q),
	    RX_DMA_DESC_BUFSIZE_DATA, MCLBYTES / 1024);
	AQ_WRITE_REG_BIT(sc, RX_DMA_DESC_BUFSIZE_REG(rx->rx_q),
	    RX_DMA_DESC_BUFSIZE_HDR, 0);
	AQ_WRITE_REG_BIT(sc, RX_DMA_DESC_REG(rx->rx_q),
	    RX_DMA_DESC_HEADER_SPLIT, 0);

#if NVLAN > 0
	strip = 1;
#else
	strip = 0;
#endif
	AQ_WRITE_REG_BIT(sc, RX_DMA_DESC_REG(rx->rx_q),
	    RX_DMA_DESC_VLAN_STRIP, strip);

	rx->rx_cons = AQ_READ_REG(sc, RX_DMA_DESC_HEAD_PTR_REG(rx->rx_q)) &
	    RX_DMA_DESC_HEAD_PTR;
	AQ_WRITE_REG(sc, RX_DMA_DESC_TAIL_PTR_REG(rx->rx_q), rx->rx_cons);
	rx->rx_prod = rx->rx_cons;

	AQ_WRITE_REG_BIT(sc, AQ_INTR_IRQ_MAP_RX_REG(rx->rx_q),
	    AQ_INTR_IRQ_MAP_RX_IRQMAP(rx->rx_q), rx->rx_irq);
	AQ_WRITE_REG_BIT(sc, AQ_INTR_IRQ_MAP_RX_REG(rx->rx_q),
	    AQ_INTR_IRQ_MAP_RX_EN(rx->rx_q), 1);

	AQ_WRITE_REG_BIT(sc, RX_DMA_DCAD_REG(rx->rx_q),
	    RX_DMA_DCAD_CPUID, 0);
	AQ_WRITE_REG_BIT(sc, RX_DMA_DCAD_REG(rx->rx_q),
	    RX_DMA_DCAD_DESC_EN, 0);
	AQ_WRITE_REG_BIT(sc, RX_DMA_DCAD_REG(rx->rx_q),
	    RX_DMA_DCAD_HEADER_EN, 0);
	AQ_WRITE_REG_BIT(sc, RX_DMA_DCAD_REG(rx->rx_q),
	    RX_DMA_DCAD_PAYLOAD_EN, 0);

	AQ_WRITE_REG_BIT(sc, RX_DMA_DESC_REG(rx->rx_q), RX_DMA_DESC_EN, 1);
}

/*
 * Fill RX ring slots with fresh mbufs for the NIC to DMA into.
 * Allocates cluster mbufs, loads their DMA addresses into the
 * RX descriptor ring, and advances the producer pointer.
 * The NIC reads descriptors between the tail pointer (producer)
 * and head pointer (consumer) to find available receive buffers.
 * Returns the number of slots that could NOT be filled.
 */
static inline unsigned int
aq_rx_fill_slots(struct aq_softc *sc, struct aq_rxring *rx, uint nslots)
{
	struct aq_rx_desc_read *ring, *rd;
	struct aq_slot *as;
	struct mbuf *m;
	uint p, fills;

	ring = AQ_DMA_KVA(&rx->rx_mem);
	p = rx->rx_prod;

	bus_dmamap_sync(sc->sc_dmat, AQ_DMA_MAP(&rx->rx_mem), 0,
	    AQ_DMA_LEN(&rx->rx_mem), BUS_DMASYNC_POSTWRITE);

	for (fills = 0; fills < nslots; fills++) {
		as = &rx->rx_slots[p];
		rd = &ring[p];

		m = MCLGETL(NULL, M_DONTWAIT, MCLBYTES + ETHER_ALIGN);
		if (m == NULL)
			break;

		m->m_data += (m->m_ext.ext_size - (MCLBYTES + ETHER_ALIGN));
		m->m_data += ETHER_ALIGN;
		m->m_len = m->m_pkthdr.len = MCLBYTES;

		if (bus_dmamap_load_mbuf(sc->sc_dmat, as->as_map, m,
		    BUS_DMA_NOWAIT) != 0) {
			m_freem(m);
			break;
		}
		as->as_m = m;

		bus_dmamap_sync(sc->sc_dmat, as->as_map, 0,
		    as->as_map->dm_mapsize, BUS_DMASYNC_PREREAD);
		htolem64(&rd->buf_addr, as->as_map->dm_segs[0].ds_addr);
		rd->hdr_addr = 0;
		p++;
		if (p == AQ_RXD_NUM)
			p = 0;
	}

	bus_dmamap_sync(sc->sc_dmat, AQ_DMA_MAP(&rx->rx_mem), 0,
	    AQ_DMA_LEN(&rx->rx_mem), BUS_DMASYNC_PREWRITE);

	rx->rx_prod = p;
	AQ_WRITE_REG(sc, RX_DMA_DESC_TAIL_PTR_REG(rx->rx_q), rx->rx_prod);
	return (nslots - fills);
}

/*
 * Refill RX ring using the if_rxring accounting framework.
 * if_rxr_get() returns how many new buffers to post, respecting
 * the ring size and livelock protection limits.
 */
int
aq_rx_fill(struct aq_softc *sc, struct aq_rxring *rx)
{
	u_int slots;

	slots = if_rxr_get(&rx->rx_rxr, AQ_RXD_NUM);
	if (slots == 0)
		return 1;

	slots = aq_rx_fill_slots(sc, rx, slots);
	if_rxr_put(&rx->rx_rxr, slots);
	return 0;
}

/*
 * Deferred RX ring refill (timeout callback).
 * If the ring runs completely empty (mbuf allocation pressure),
 * we can't refill from the interrupt handler.  This timeout
 * retries periodically until buffers become available.
 */
void
aq_refill(void *xq)
{
	struct aq_queues *q = xq;
	struct aq_softc *sc = q->q_sc;

	aq_rx_fill(sc, &q->q_rx);

	if (if_rxr_inuse(&q->q_rx.rx_rxr) == 0)
		timeout_add(&q->q_rx.rx_refill, 1);
}

/*
 * RX completion handler - process received packets.
 *
 * Called from the interrupt handler.  Reads the hardware head pointer
 * to determine how many descriptors have been written back by the NIC.
 * For each completed descriptor:
 *   - Unloads the DMA mapping and retrieves the mbuf
 *   - Checks the writeback status for errors (MAC, DMA)
 *   - Extracts RSS hash, VLAN tag, and checksum offload results
 *   - Assembles multi-descriptor packets (jumbo frames)
 *   - Enqueues complete packets into an mbuf_list
 *
 * After processing, hands the packet list to ifiq_input() which
 * delivers them to the network stack.  Then refills the ring.
 * If ifiq_input returns nonzero, the input queue is congested
 * (livelock protection triggers).
 */
void
aq_rxeof(struct aq_softc *sc, struct aq_rxring *rx)
{
	struct ifnet *ifp = &sc->sc_arpcom.ac_if;
	struct aq_rx_desc_wb *rxd;
	struct aq_rx_desc_wb *ring;
	struct aq_slot *as;
	uint32_t end, idx;
	uint16_t pktlen, status;
	uint32_t rxd_type;
	struct mbuf *m, *mb;
	struct mbuf_list ml = MBUF_LIST_INITIALIZER();
	int rxfree;

	if (!ISSET(ifp->if_flags, IFF_RUNNING))
		return;

	end = AQ_READ_REG(sc, RX_DMA_DESC_HEAD_PTR_REG(rx->rx_q)) &
	    RX_DMA_DESC_HEAD_PTR;

	bus_dmamap_sync(sc->sc_dmat, AQ_DMA_MAP(&rx->rx_mem), 0,
	    AQ_DMA_LEN(&rx->rx_mem), BUS_DMASYNC_POSTREAD);

	rxfree = 0;
	idx = rx->rx_cons;
	ring = AQ_DMA_KVA(&rx->rx_mem);
	while (idx != end) {
		rxd = &ring[idx];
		as = &rx->rx_slots[idx];

		bus_dmamap_sync(sc->sc_dmat, as->as_map, 0,
		    as->as_map->dm_mapsize, BUS_DMASYNC_POSTREAD);
		bus_dmamap_unload(sc->sc_dmat, as->as_map);

		status = lemtoh16(&rxd->status);
		if ((status & AQ_RXDESC_STATUS_DD) == 0)
			break;

		rxfree++;
		mb = as->as_m;
		as->as_m = NULL;

		pktlen = lemtoh16(&rxd->pkt_len);
		rxd_type = lemtoh32(&rxd->type);
		if ((rxd_type & AQ_RXDESC_TYPE_RSSTYPE) != 0) {
			mb->m_pkthdr.ph_flowid = lemtoh32(&rxd->rss_hash);
			mb->m_pkthdr.csum_flags |= M_FLOWID;
		}

		mb->m_pkthdr.len = 0;
		mb->m_next = NULL;
		*rx->rx_m_tail = mb;
		rx->rx_m_tail = &mb->m_next;

		m = rx->rx_m_head;

#if NVLAN > 0
		if (rxd_type & (AQ_RXDESC_TYPE_VLAN | AQ_RXDESC_TYPE_VLAN2)) {
			m->m_pkthdr.ether_vtag = lemtoh16(&rxd->vlan);
			m->m_flags |= M_VLANTAG;
		}
#endif

		if ((rxd_type & AQ_RXDESC_TYPE_V4_SUM) &&
		    ((status & AQ_RXDESC_STATUS_V4_SUM_NG) == 0))
			m->m_pkthdr.csum_flags |= M_IPV4_CSUM_IN_OK;

		if ((rxd_type & AQ_RXDESC_TYPE_L4_SUM) &&
		   (status & AQ_RXDESC_STATUS_L4_SUM_OK))
			m->m_pkthdr.csum_flags |= M_UDP_CSUM_IN_OK |
			    M_TCP_CSUM_IN_OK;

		if ((status & AQ_RXDESC_STATUS_MACERR) ||
		    (rxd_type & AQ_RXDESC_TYPE_DMA_ERR)) {
			printf("%s:rx: rx error (status %x type %x)\n",
			    DEVNAME(sc), status, rxd_type);
			rx->rx_m_error = 1;
		}

		if (status & AQ_RXDESC_STATUS_EOP) {
			mb->m_len = pktlen - m->m_pkthdr.len;
			m->m_pkthdr.len = pktlen;
			if (rx->rx_m_error != 0) {
				ifp->if_ierrors++;
				m_freem(m);
			} else {
				ml_enqueue(&ml, m);
			}

			rx->rx_m_head = NULL;
			rx->rx_m_tail = &rx->rx_m_head;
			rx->rx_m_error = 0;
		} else {
			mb->m_len = MCLBYTES;
			m->m_pkthdr.len += mb->m_len;
		}

		idx++;
		if (idx == AQ_RXD_NUM)
			idx = 0;
	}

	bus_dmamap_sync(sc->sc_dmat, AQ_DMA_MAP(&rx->rx_mem), 0,
	    AQ_DMA_LEN(&rx->rx_mem), BUS_DMASYNC_PREREAD);

	rx->rx_cons = idx;

	if (rxfree > 0) {
		if_rxr_put(&rx->rx_rxr, rxfree);
		if (ifiq_input(rx->rx_ifiq, &ml))
			if_rxr_livelocked(&rx->rx_rxr);

		aq_rx_fill(sc, rx);
		if (if_rxr_inuse(&rx->rx_rxr) == 0)
			timeout_add(&rx->rx_refill, 1);
	}
}

/*
 * TX completion handler - reclaim transmitted descriptors.
 *
 * Called from the interrupt handler.  Reads the hardware head pointer
 * to see how far the NIC has progressed through the TX ring.  For
 * each completed descriptor, unloads the DMA mapping and frees the
 * mbuf.  If the queue was stalled (oactive), restarts transmission.
 */
void
aq_txeof(struct aq_softc *sc, struct aq_txring *tx)
{
	struct ifnet *ifp = &sc->sc_arpcom.ac_if;
	struct aq_slot *as;
	uint32_t idx, end, free;

	if (!ISSET(ifp->if_flags, IFF_RUNNING))
		return;

	idx = tx->tx_cons;
	end = AQ_READ_REG(sc, TX_DMA_DESC_HEAD_PTR_REG(tx->tx_q)) &
	    TX_DMA_DESC_HEAD_PTR;
	free = 0;

	bus_dmamap_sync(sc->sc_dmat, AQ_DMA_MAP(&tx->tx_mem), 0,
	    AQ_DMA_LEN(&tx->tx_mem), BUS_DMASYNC_POSTREAD);

	while (idx != end) {
		as = &tx->tx_slots[idx];

		if (as->as_m != NULL) {
			bus_dmamap_sync(sc->sc_dmat, as->as_map, 0,
			    as->as_map->dm_mapsize, BUS_DMASYNC_POSTWRITE);
			bus_dmamap_unload(sc->sc_dmat, as->as_map);

			m_freem(as->as_m);
			as->as_m = NULL;
		}

		idx++;
		if (idx == AQ_TXD_NUM)
			idx = 0;
		free++;
	}

	bus_dmamap_sync(sc->sc_dmat, AQ_DMA_MAP(&tx->tx_mem), 0,
	    AQ_DMA_LEN(&tx->tx_mem), BUS_DMASYNC_PREREAD);

	tx->tx_cons = idx;

	if (free != 0) {
		if (ifq_is_oactive(tx->tx_ifq))
			ifq_restart(tx->tx_ifq);
	}
}

/*
 * Transmit start function (ifq_start callback).
 *
 * Called by the network stack when packets are enqueued.  Dequeues
 * mbufs from the interface queue, maps them for DMA, and writes
 * TX descriptors.  Handles:
 *   - Multi-segment packets (scatter-gather DMA)
 *   - VLAN tag insertion via context descriptors (TXC)
 *   - IPv4/TCP/UDP checksum offload flags
 *   - EFBIG recovery via m_defrag()
 *   - BPF tap for packet capture
 *
 * The last segment of each packet gets EOP (end of packet) and WB
 * (write back) flags so the NIC knows when transmission is complete.
 * After filling descriptors, advances the tail pointer to kick the
 * NIC's DMA engine.
 */
void
aq_start(struct ifqueue *ifq)
{
	struct aq_queues *aq = ifq->ifq_softc;
	struct aq_softc *sc = aq->q_sc;
	struct aq_txring *tx = &aq->q_tx;
	struct aq_tx_desc *ring, *txd;
	struct aq_slot *as;
	struct mbuf *m;
	uint32_t idx, free, used, ctl1, ctl2;
	uint32_t txc_ctl1, txc_ctl2;
	int need_txc;
	int error, i;

	if (!LINK_STATE_IS_UP(sc->sc_arpcom.ac_if.if_link_state)) {
		ifq_purge(ifq);
		return;
	}

	idx = tx->tx_prod;
	free = tx->tx_cons + AQ_TXD_NUM - tx->tx_prod;
	used = 0;

	bus_dmamap_sync(sc->sc_dmat, AQ_DMA_MAP(&tx->tx_mem), 0,
	    AQ_DMA_LEN(&tx->tx_mem), BUS_DMASYNC_POSTWRITE);
	ring = (struct aq_tx_desc *)AQ_DMA_KVA(&tx->tx_mem);

	for (;;) {
		if (used + AQ_TX_MAX_SEGMENTS + 1 >= free) {
			ifq_set_oactive(ifq);
			break;
		}

		m = ifq_dequeue(ifq);
		if (m == NULL)
			break;

		as = &tx->tx_slots[idx];

		error = bus_dmamap_load_mbuf(sc->sc_dmat, as->as_map, m,
		    BUS_DMA_STREAMING | BUS_DMA_NOWAIT);
		if (error == EFBIG) {
			if (m_defrag(m, M_DONTWAIT)) {
				m_freem(m);
				break;
			}

			error = bus_dmamap_load_mbuf(sc->sc_dmat, as->as_map,
			    m, BUS_DMA_STREAMING | BUS_DMA_NOWAIT);
		}
		if (error != 0) {
			m_freem(m);
			break;
		}

		as->as_m = m;

#if NBPFILTER > 0
		if (ifq->ifq_if->if_bpf)
			bpf_mtap_ether(ifq->ifq_if->if_bpf, m, BPF_DIRECTION_OUT);
#endif
		bus_dmamap_sync(sc->sc_dmat, as->as_map, 0,
		    as->as_map->dm_mapsize, BUS_DMASYNC_PREWRITE);

		ctl2 = m->m_pkthdr.len << AQ_TXDESC_CTL2_LEN_SHIFT;
		ctl1 = AQ_TXDESC_CTL1_TYPE_TXD | AQ_TXDESC_CTL1_CMD_FCS;
		txc_ctl1 = 0;
		txc_ctl2 = 0;
		need_txc = 0;

#if NVLAN > 0
		if (m->m_flags & M_VLANTAG) {
			txc_ctl1 |= (m->m_pkthdr.ether_vtag <<
			    AQ_TXDESC_CTL1_VLAN_SHIFT);
			ctl1 |= AQ_TXDESC_CTL1_CMD_VLAN;
			need_txc = 1;
		}
#endif

		if (m->m_pkthdr.csum_flags & M_TCP_TSO) {
			struct ether_extracted ext;

			ether_extract_headers(m, &ext);

			if (ext.tcp && m->m_pkthdr.ph_mss > 0) {
				uint32_t l2len, l3len, l4len, cmd;
				uint32_t paylen, mss;

				if (ext.ip4)
					l2len = (uint8_t *)ext.ip4 -
					    mtod(m, uint8_t *);
				else if (ext.ip6)
					l2len = (uint8_t *)ext.ip6 -
					    mtod(m, uint8_t *);
				else {
					tcpstat_inc(tcps_outbadtso);
					goto notso;
				}
				l3len = ext.iphlen;
				l4len = ext.tcphlen;
				mss = m->m_pkthdr.ph_mss;

				cmd = AQ_TXC_CMD_LSO;
				if (ext.ip6 != NULL)
					cmd |= AQ_TXC_CMD_IPV6;

				txc_ctl1 |= (cmd << AQ_TXC_CTL1_CMD_SHIFT);
				txc_ctl1 |= (l2len << AQ_TXC_CTL1_L2LEN_SHIFT);
				txc_ctl1 |= ((l3len & 0x1) << 31);

				txc_ctl2 |= ((l3len >> 1) << AQ_TXC_CTL2_L3LEN_SHIFT);
				txc_ctl2 |= (l4len << AQ_TXC_CTL2_L4LEN_SHIFT);
				txc_ctl2 |= (mss << AQ_TXC_CTL2_MSS_SHIFT);

				ctl1 |= AQ_TXDESC_CTL1_CMD_LSO;
				if (ext.ip4)
					ctl1 |=
					    AQ_TXDESC_CTL1_CMD_IP4CSUM;
				ctl1 |= AQ_TXDESC_CTL1_CMD_L4CSUM;
				need_txc = 1;

				paylen = m->m_pkthdr.len - l2len -
				    l3len - l4len;
				ctl2 = paylen <<
				    AQ_TXDESC_CTL2_LEN_SHIFT;
				tcpstat_add(tcps_outpkttso,
				    (paylen + mss - 1) / mss);
			} else {
				tcpstat_inc(tcps_outbadtso);
			}
		}
 notso:

		if (need_txc) {
			txd = ring + idx;
			txd->buf_addr = 0;
			txd->ctl1 = htole32(AQ_TXDESC_CTL1_TYPE_TXC |
			    txc_ctl1);
			txd->ctl2 = htole32(txc_ctl2);
			ctl2 |= AQ_TXDESC_CTL2_CTX_EN;

			idx++;
			if (idx == AQ_TXD_NUM)
				idx = 0;
			used++;
		}

		if (!(m->m_pkthdr.csum_flags & M_TCP_TSO)) {
			if (m->m_pkthdr.csum_flags & M_IPV4_CSUM_OUT)
				ctl1 |= AQ_TXDESC_CTL1_CMD_IP4CSUM;
			if (m->m_pkthdr.csum_flags &
			    (M_TCP_CSUM_OUT | M_UDP_CSUM_OUT))
				ctl1 |= AQ_TXDESC_CTL1_CMD_L4CSUM;
		}

		for (i = 0; i < as->as_map->dm_nsegs; i++) {

			if (i == as->as_map->dm_nsegs - 1)
				ctl1 |= AQ_TXDESC_CTL1_CMD_EOP |
				    AQ_TXDESC_CTL1_CMD_WB;

			txd = ring + idx;
			txd->buf_addr = htole64(as->as_map->dm_segs[i].ds_addr);
			txd->ctl1 = htole32(ctl1 |
			    (as->as_map->dm_segs[i].ds_len <<
			    AQ_TXDESC_CTL1_BLEN_SHIFT));
			txd->ctl2 = htole32(ctl2);

			idx++;
			if (idx == AQ_TXD_NUM)
				idx = 0;
			used++;
		}
	}

	bus_dmamap_sync(sc->sc_dmat, AQ_DMA_MAP(&tx->tx_mem), 0,
	    AQ_DMA_LEN(&tx->tx_mem), BUS_DMASYNC_PREWRITE);

	if (used != 0) {
		tx->tx_prod = idx;
		AQ_WRITE_REG(sc, TX_DMA_DESC_TAIL_PTR_REG(tx->tx_q),
		    tx->tx_prod);
	}
}

/*
 * Per-queue interrupt handler (MSI-X multi-vector mode).
 * Each queue gets its own MSI-X vector and interrupt handler,
 * bound to a specific CPU for cache locality.  Handles both
 * TX completion and RX completion for one queue pair.
 */
int
aq_intr_queue(void *arg)
{
	struct aq_queues *aq = arg;
	struct aq_softc *sc = aq->q_sc;
	uint32_t status;
	uint32_t clear;

	status = AQ_READ_REG(sc, AQ_INTR_STATUS_REG);
	clear = 0;
	if (status & (1 << aq->q_tx.tx_irq)) {
		clear |= (1 << aq->q_tx.tx_irq);
		aq_txeof(sc, &aq->q_tx);
	}

	if (status & (1 << aq->q_rx.rx_irq)) {
		clear |= (1 << aq->q_rx.rx_irq);
		aq_rxeof(sc, &aq->q_rx);
	}

	AQ_WRITE_REG(sc, AQ_INTR_STATUS_CLR_REG, clear);
	return (clear != 0);
}

/*
 * Link status change interrupt handler (MSI-X vector 0).
 * In multi-vector mode, vector 0 is dedicated to link status.
 * Calls aq_update_link_status() to check for link up/down.
 */
int
aq_intr_link(void *arg)
{
	struct aq_softc *sc = arg;
	uint32_t status;

	status = AQ_READ_REG(sc, AQ_INTR_STATUS_REG);
	if (status & (1 << sc->sc_linkstat_irq)) {
		aq_update_link_status(sc);
		AQ_WRITE_REG(sc, AQ_INTR_STATUS_REG, (1 << sc->sc_linkstat_irq));
		return 1;
	}

	return 0;
}

/*
 * Combined interrupt handler (single vector: MSI or legacy mode).
 * Handles link status, TX completion, and RX completion all from
 * one interrupt.  Only queue 0 is used in this mode.
 */
int
aq_intr(void *arg)
{
	struct aq_softc *sc = arg;
	struct aq_queues *aq = &sc->sc_queues[0];
	uint32_t status;

	status = AQ_READ_REG(sc, AQ_INTR_STATUS_REG);
	AQ_WRITE_REG(sc, AQ_INTR_STATUS_CLR_REG, 0xffffffff);

	if (status & (1 << sc->sc_linkstat_irq))
		aq_update_link_status(sc);

	if (status & (1 << aq->q_tx.tx_irq)) {
		aq_txeof(sc, &aq->q_tx);
		AQ_WRITE_REG(sc, AQ_INTR_STATUS_CLR_REG,
		    (1 << aq->q_tx.tx_irq));
	}
	if (status & (1 << aq->q_rx.rx_irq)) {
		aq_rxeof(sc, &aq->q_rx);
		AQ_WRITE_REG(sc, AQ_INTR_STATUS_CLR_REG,
		    (1 << aq->q_rx.rx_irq));
	}

	return 1;
}

void
aq_watchdog(struct ifnet *ifp)
{

}

/* Free DMA maps and any remaining mbufs for a ring's slot array. */
void
aq_free_slots(struct aq_softc *sc, struct aq_slot *slots, int allocated,
    int total)
{
	struct aq_slot *as;

	int i = allocated;
	while (i-- > 0) {
		as = &slots[i];
		bus_dmamap_destroy(sc->sc_dmat, as->as_map);
		if (as->as_m != NULL)
			m_freem(as->as_m);
	}
	free(slots, M_DEVBUF, total * sizeof(*as));
}

/*
 * Allocate resources for one TX/RX queue pair.
 * Creates DMA maps for each slot, allocates DMA memory for the
 * descriptor rings, and programs the hardware ring registers.
 * On failure, tears down any partially-allocated resources.
 */
int
aq_queue_up(struct aq_softc *sc, struct aq_queues *aq)
{
	struct aq_rxring *rx;
	struct aq_txring *tx;
	struct aq_slot *as;
	int i;

	rx = &aq->q_rx;
	rx->rx_slots = mallocarray(sizeof(*as), AQ_RXD_NUM, M_DEVBUF,
	    M_WAITOK | M_ZERO);
	if (rx->rx_slots == NULL) {
		printf("%s: failed to allocate rx slots %d\n", DEVNAME(sc),
		    aq->q_index);
		return ENOMEM;
	}

	for (i = 0; i < AQ_RXD_NUM; i++) {
		as = &rx->rx_slots[i];
		if (bus_dmamap_create(sc->sc_dmat, MCLBYTES, 1, MCLBYTES, 0,
		    BUS_DMA_WAITOK | BUS_DMA_ALLOCNOW | BUS_DMA_64BIT,
		    &as->as_map) != 0) {
			printf("%s: failed to allocate rx dma maps %d\n",
			    DEVNAME(sc), aq->q_index);
			goto destroy_rx_slots;
		}
	}

	if (aq_dmamem_alloc(sc, &rx->rx_mem, AQ_RXD_NUM *
	    sizeof(struct aq_rx_desc_read), PAGE_SIZE) != 0) {
		printf("%s: unable to allocate rx ring %d\n", DEVNAME(sc),
		    aq->q_index);
		goto destroy_rx_slots;
	}

	tx = &aq->q_tx;
	tx->tx_slots = mallocarray(sizeof(*as), AQ_TXD_NUM, M_DEVBUF,
	    M_WAITOK | M_ZERO);
	if (tx->tx_slots == NULL) {
		printf("%s: failed to allocate tx slots %d\n", DEVNAME(sc),
		    aq->q_index);
		goto destroy_rx_ring;
	}

	for (i = 0; i < AQ_TXD_NUM; i++) {
		as = &tx->tx_slots[i];
		if (bus_dmamap_create(sc->sc_dmat, MAXMCLBYTES,
		    AQ_TX_MAX_SEGMENTS, MCLBYTES, 0,
		    BUS_DMA_WAITOK | BUS_DMA_ALLOCNOW | BUS_DMA_64BIT,
		    &as->as_map) != 0) {
			printf("%s: failed to allocated tx dma maps %d\n",
			    DEVNAME(sc), aq->q_index);
			goto destroy_tx_slots;
		}
	}

	if (aq_dmamem_alloc(sc, &tx->tx_mem, AQ_TXD_NUM *
	    sizeof(struct aq_tx_desc), PAGE_SIZE) != 0) {
		printf("%s: unable to allocate tx ring %d\n", DEVNAME(sc),
		    aq->q_index);
		goto destroy_tx_slots;
	}

	bus_dmamap_sync(sc->sc_dmat, AQ_DMA_MAP(&tx->tx_mem),
	    0, AQ_DMA_LEN(&tx->tx_mem),
	    BUS_DMASYNC_PREREAD|BUS_DMASYNC_PREWRITE);

	bus_dmamap_sync(sc->sc_dmat, AQ_DMA_MAP(&rx->rx_mem),
	    0, AQ_DMA_LEN(&rx->rx_mem),
	    BUS_DMASYNC_PREREAD|BUS_DMASYNC_PREWRITE);

	aq_txring_reset(sc, tx, 1);
	aq_rxring_reset(sc, rx, 1);
	return 0;

destroy_tx_slots:
	aq_free_slots(sc, tx->tx_slots, i, AQ_TXD_NUM);
	tx->tx_slots = NULL;
	i = AQ_RXD_NUM;

destroy_rx_ring:
	aq_dmamem_free(sc, &rx->rx_mem);
destroy_rx_slots:
	aq_free_slots(sc, rx->rx_slots, i, AQ_RXD_NUM);
	rx->rx_slots = NULL;
	return ENOMEM;
}

/* Tear down one TX/RX queue pair: disable rings, free slots and DMA memory. */
void
aq_queue_down(struct aq_softc *sc, struct aq_queues *aq)
{
	struct aq_txring *tx;
	struct aq_rxring *rx;

	tx = &aq->q_tx;
	aq_txring_reset(sc, &aq->q_tx, 0);
	if (tx->tx_slots != NULL) {
		aq_free_slots(sc, tx->tx_slots, AQ_TXD_NUM, AQ_TXD_NUM);
		tx->tx_slots = NULL;
	}

	bus_dmamap_sync(sc->sc_dmat, AQ_DMA_MAP(&tx->tx_mem),
	    0, AQ_DMA_LEN(&tx->tx_mem),
	    BUS_DMASYNC_POSTREAD|BUS_DMASYNC_POSTWRITE);

	aq_dmamem_free(sc, &tx->tx_mem);

	rx = &aq->q_rx;
	m_freem(rx->rx_m_head);
	rx->rx_m_head = NULL;
	rx->rx_m_tail = &rx->rx_m_head;
	rx->rx_m_error = 0;
	aq_rxring_reset(sc, &aq->q_rx, 0);
	if (rx->rx_slots != NULL) {
		aq_free_slots(sc, rx->rx_slots, AQ_RXD_NUM, AQ_RXD_NUM);
		rx->rx_slots = NULL;
	}

	bus_dmamap_sync(sc->sc_dmat, AQ_DMA_MAP(&rx->rx_mem),
	    0, AQ_DMA_LEN(&rx->rx_mem),
	    BUS_DMASYNC_POSTREAD|BUS_DMASYNC_POSTWRITE);

	aq_dmamem_free(sc, &rx->rx_mem);
}

/*
 * Toggle the RX descriptor cache init bit.
 * The NIC caches RX descriptors internally; this forces it to re-read
 * them from memory.  Called when bringing the interface up or down.
 */
void
aq_invalidate_rx_desc_cache(struct aq_softc *sc)
{
	uint32_t cache;

	cache = AQ_READ_REG(sc, RX_DMA_DESC_CACHE_INIT_REG);
	AQ_WRITE_REG_BIT(sc, RX_DMA_DESC_CACHE_INIT_REG, RX_DMA_DESC_CACHE_INIT,
	    (cache & RX_DMA_DESC_CACHE_INIT) ^ RX_DMA_DESC_CACHE_INIT);
}

/*
 * Bring the interface up.
 * Invalidates the RX descriptor cache, allocates and initializes all
 * queue pairs (DMA rings, slot arrays, hardware ring registers),
 * programs the MAC address, enables hardware checksum offload,
 * enables interrupts and TX/RX buffers, initializes the rxring
 * accounting, fills RX rings with mbufs, and marks queues active.
 */
int
aq_up(struct aq_softc *sc)
{
	struct ifnet *ifp = &sc->sc_arpcom.ac_if;
	uint32_t lro_en;
	int i;

	aq_invalidate_rx_desc_cache(sc);

	for (i = 0; i < sc->sc_nqueues; i++) {
		if (aq_queue_up(sc, &sc->sc_queues[i]) != 0)
			goto downqueues;
	}

	aq_set_mac_addr(sc, AQ_HW_MAC_OWN, sc->sc_arpcom.ac_enaddr);

	AQ_WRITE_REG_BIT(sc, TPO_HWCSUM_REG, TPO_HWCSUM_IP4CSUM_EN, 1);
	AQ_WRITE_REG_BIT(sc, TPO_HWCSUM_REG, TPO_HWCSUM_L4CSUM_EN, 1);

	/* Hardware LSO / Large Send Offload */
	AQ_WRITE_REG(sc, TDM_LSO_ENABLE, 0xffffffff);

	AQ_WRITE_REG_BIT(sc, RPO_HWCSUM_REG, RPO_HWCSUM_IP4CSUM_EN, 1);
	AQ_WRITE_REG_BIT(sc, RPO_HWCSUM_REG, RPO_HWCSUM_L4CSUM_EN, 1);

	/* Hardware LRO / Receive Side Coalescing */
	for (i = 0; i < 32; i++)
		AQ_WRITE_REG_BIT(sc, RPO_LRO_DESC_MAX_REG(i),
		    RPO_LRO_DESC_MAX_MASK(i), 0x3);
	AQ_WRITE_REG_BIT(sc, RPO_LRO_TIMER_REG, RPO_LRO_TIMER_TB_DIV, 0x61a);
	AQ_WRITE_REG_BIT(sc, RPO_LRO_TIMER_REG, RPO_LRO_TIMER_INA_IVAL, 0);
	AQ_WRITE_REG_BIT(sc, RPO_LRO_TIMER_REG, RPO_LRO_TIMER_MAX_IVAL, 50);
	AQ_WRITE_REG_BIT(sc, RPO_LRO_CONF_REG, RPO_LRO_CONF_QSES_LMT, 1);
	AQ_WRITE_REG_BIT(sc, RPO_LRO_CONF_REG, RPO_LRO_CONF_TOT_DSC_LMT, 2);
	AQ_WRITE_REG_BIT(sc, RPO_LRO_CONF_REG, RPO_LRO_CONF_PTOPT_EN, 1);
	AQ_WRITE_REG_BIT(sc, RPO_LRO_CONF_REG, RPO_LRO_CONF_PKT_MIN, 10);
	AQ_WRITE_REG(sc, RPO_LRO_RSC_MAX_REG, 1);

	lro_en = ISSET(ifp->if_xflags, IFXF_LRO) ? 0xffffffff : 0;
	DPRINTF(("%s: LRO is %s", DEVNAME(sc), lro_en ? "enabled" : "disabled"));
	AQ_WRITE_REG(sc, RPO_LRO_EN_REG, lro_en);
	AQ_WRITE_REG(sc, ITR_RSC_EN_REG, lro_en);

	AQ_WRITE_REG_BIT(sc, ITR_RSC_DELAY_REG, ITR_RSC_DELAY, 1);

	SET(ifp->if_flags, IFF_RUNNING);
	aq_enable_intr(sc, 1, 1);
	AQ_WRITE_REG_BIT(sc, TPB_TX_BUF_REG, TPB_TX_BUF_EN, 1);
	AQ_WRITE_REG_BIT(sc, RPB_RPF_RX_REG, RPB_RPF_RX_BUF_EN, 1);

	for (i = 0; i < sc->sc_nqueues; i++) {
		struct aq_queues *aq = &sc->sc_queues[i];

		if_rxr_init(&aq->q_rx.rx_rxr, howmany(ifp->if_hardmtu, MCLBYTES),
		    AQ_RXD_NUM - 1);
		aq_rx_fill(sc, &aq->q_rx);

		ifq_clr_oactive(aq->q_tx.tx_ifq);
	}

	return ENETRESET;

downqueues:
	for (i = 0; i < sc->sc_nqueues; i++)
		aq_queue_down(sc, &sc->sc_queues[i]);
	return ENOMEM;
}

/*
 * Bring the interface down.
 * Clears IFF_RUNNING, disables TX/RX interrupts, waits for any
 * in-flight interrupt handlers to complete (intr_barrier), disables
 * the RX buffer, tears down all queue pairs, and invalidates the
 * RX descriptor cache.
 */
void
aq_down(struct aq_softc *sc)
{
	struct ifnet *ifp = &sc->sc_arpcom.ac_if;
	int i;

	CLR(ifp->if_flags, IFF_RUNNING);

	aq_enable_intr(sc, 1, 0);
	intr_barrier(sc->sc_ih);

	AQ_WRITE_REG_BIT(sc, RPB_RPF_RX_REG, RPB_RPF_RX_BUF_EN, 0);
	for (i = 0; i < sc->sc_nqueues; i++) {
		/* queue intr barrier? */
		aq_queue_down(sc, &sc->sc_queues[i]);
	}

	aq_invalidate_rx_desc_cache(sc);
}

/*
 * Enable or reconfigure the interrupt mask.
 * Builds a bitmask of all active interrupt sources (TX/RX queues
 * and link status) and writes it to the interrupt mask register.
 * Also clears any pending interrupts.
 */
void
aq_enable_intr(struct aq_softc *sc, int link, int txrx)
{
	uint32_t imask = 0;
	int i;

	if (txrx) {
		for (i = 0; i < sc->sc_nqueues; i++) {
			imask |= (1 << sc->sc_queues[i].q_tx.tx_irq);
			imask |= (1 << sc->sc_queues[i].q_rx.rx_irq);
		}
	}

	if (link)
		imask |= (1 << sc->sc_linkstat_irq);

	AQ_WRITE_REG(sc, AQ_INTR_MASK_REG, imask);
	AQ_WRITE_REG(sc, AQ_INTR_STATUS_CLR_REG, 0xffffffff);
}

/*
 * Report current media status (ifconfig / ifmedia).
 * Queries the firmware for the current negotiated link speed and
 * flow control, then translates to the ifmedia framework constants.
 */
void
aq_ifmedia_status(struct ifnet *ifp, struct ifmediareq *ifmr)
{
	struct aq_softc *aq = ifp->if_softc;
	enum aq_link_speed speed;
	enum aq_link_fc fc;
	int media;
	int flow;

	if (aq_get_linkmode(aq, &speed, &fc, NULL) != 0)
		return;

	switch (speed) {
	case AQ_LINK_10G:
		media = IFM_10G_T;
		break;
	case AQ_LINK_5G:
		media = IFM_5000_T;
		break;
	case AQ_LINK_2G5:
		media = IFM_2500_T;
		break;
	case AQ_LINK_1G:
		media = IFM_1000_T;
		break;
	case AQ_LINK_100M:
		media = IFM_100_TX;
		break;
	case AQ_LINK_10M:
		media = IFM_10_T;
		break;
	case AQ_LINK_NONE:
		media = 0;
		break;
	}

	flow = 0;
	if (fc & AQ_FC_RX)
		flow |= IFM_ETH_RXPAUSE;
	if (fc & AQ_FC_TX)
		flow |= IFM_ETH_TXPAUSE;

	ifmr->ifm_status = IFM_AVALID;
	if (speed != AQ_LINK_NONE) {
		ifmr->ifm_status |= IFM_ACTIVE;
		ifmr->ifm_active = IFM_ETHER | IFM_AUTO | media | flow;
	}
}

/*
 * Handle media change request (e.g. "ifconfig aq0 media 1000baseT").
 * Translates the ifmedia selection to the driver's link speed enum
 * and calls aq_set_linkmode() to reprogram the firmware.
 */
int
aq_ifmedia_change(struct ifnet *ifp)
{
	struct aq_softc *sc = ifp->if_softc;
	enum aq_link_speed rate = AQ_LINK_NONE;
	enum aq_link_fc fc = AQ_FC_NONE;

	if (IFM_TYPE(sc->sc_media.ifm_media) != IFM_ETHER)
		return EINVAL;

	switch (IFM_SUBTYPE(sc->sc_media.ifm_media)) {
	case IFM_AUTO:
		rate = AQ_LINK_AUTO;
		break;
	case IFM_NONE:
		rate = AQ_LINK_NONE;
		break;
	case IFM_10_T:
		rate = AQ_LINK_10M;
		break;
	case IFM_100_TX:
		rate = AQ_LINK_100M;
		break;
	case IFM_1000_T:
		rate = AQ_LINK_1G;
		break;
	case IFM_2500_T:
		rate = AQ_LINK_2G5;
		break;
	case IFM_5000_T:
		rate = AQ_LINK_5G;
		break;
	case IFM_10G_T:
		rate = AQ_LINK_10G;
		break;
	default:
		return ENODEV;
	}

	if (sc->sc_media.ifm_media & IFM_FLOW)
		fc = AQ_FC_ALL;

	return aq_set_linkmode(sc, rate, fc, AQ_EEE_DISABLE);
}

/*
 * Check for link state transitions and notify the network stack.
 * Called from the link status interrupt handler.  Queries the firmware
 * for the current speed; if it changed, calls if_link_state_change()
 * so the routing table and userland (dhclient, etc.) are notified.
 */
void
aq_update_link_status(struct aq_softc *sc)
{
	struct ifnet *ifp = &sc->sc_arpcom.ac_if;
	enum aq_link_speed speed;
	enum aq_link_fc fc;

	if (aq_get_linkmode(sc, &speed, &fc, NULL) != 0)
		return;

	if (speed == AQ_LINK_NONE) {
		if (ifp->if_link_state != LINK_STATE_DOWN) {
			ifp->if_link_state = LINK_STATE_DOWN;
			if_link_state_change(ifp);
		}
	} else {
		if (ifp->if_link_state != LINK_STATE_FULL_DUPLEX) {
			ifp->if_link_state = LINK_STATE_FULL_DUPLEX;
			if_link_state_change(ifp);
		}
	}
}

/*
 * Report RX ring info (SIOCGIFRXR ioctl).
 * Returns per-queue buffer size and ring state for monitoring tools.
 */
int
aq_rxrinfo(struct aq_softc *sc, struct if_rxrinfo *ifri)
{
	struct if_rxring_info *ifr;
	int i;
	int error;

	ifr = mallocarray(sc->sc_nqueues, sizeof(*ifr), M_TEMP,
	    M_WAITOK | M_ZERO | M_CANFAIL);
	if (ifr == NULL)
		return (ENOMEM);

	for (i = 0; i < sc->sc_nqueues; i++) {
		ifr[i].ifr_size = MCLBYTES;
		ifr[i].ifr_info = sc->sc_queues[i].q_rx.rx_rxr;
	}

	error = if_rxr_info_ioctl(ifri, sc->sc_nqueues, ifr);
	free(ifr, M_TEMP, sc->sc_nqueues * sizeof(*ifr));

	return (error);
}

/*
 * ioctl handler for the network interface.
 * Handles standard network ioctls:
 *   SIOCSIFADDR   - set address (bring up if needed)
 *   SIOCSIFFLAGS  - set flags (up/down, promisc, etc.)
 *   SIOCSIFMEDIA  - set media type
 *   SIOCGIFMEDIA  - get media type
 *   SIOCGIFRXR    - get RX ring info
 *   SIOCGIFSFFPAGE - read SFP module data (fibre only)
 * Falls through to ether_ioctl() for multicast and other Ethernet ops.
 * On ENETRESET, calls aq_iff() to reprogram the packet filter.
 */
int
aq_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct aq_softc *sc = ifp->if_softc;
	struct ifreq *ifr = (struct ifreq *)data;
	int error = 0, s;

	s = splnet();

	switch (cmd) {
	case SIOCSIFADDR:
		ifp->if_flags |= IFF_UP;
		if ((ifp->if_flags & IFF_RUNNING) == 0)
			error = aq_up(sc);
		break;
	case SIOCSIFFLAGS:
		if (ifp->if_flags & IFF_UP) {
			if (ifp->if_flags & IFF_RUNNING)
				error = ENETRESET;
			else
				error = aq_up(sc);
		} else {
			if (ifp->if_flags & IFF_RUNNING)
				aq_down(sc);
		}
		break;
	case SIOCSIFMEDIA:
	case SIOCGIFMEDIA:
		error = ifmedia_ioctl(ifp, ifr, &sc->sc_media, cmd);
		break;

	case SIOCGIFRXR:
		error = aq_rxrinfo(sc, (struct if_rxrinfo *)ifr->ifr_data);
		break;

	case SIOCGIFSFFPAGE:
		if (sc->sc_media_type == AQ_MEDIA_TYPE_FIBRE)
			error = aq_get_sffpage(sc, (struct if_sffpage *)data);
		else
			error = ENXIO;
		break;

	default:
		error = ether_ioctl(ifp, &sc->sc_arpcom, cmd, data);
	}

	if (error == ENETRESET) {
		if (ifp->if_flags & IFF_RUNNING)
			aq_iff(sc);
		error = 0;
	}

	splx(s);
	return error;
}

/*
 * Program one entry in the AQ2 Action Resolver Table.
 * Acquires the ART semaphore for mutual exclusion with firmware,
 * writes the tag/mask/action triple at the given index (offset by
 * the base index read from firmware capabilities).
 */
int
aq2_filter_art_set(struct aq_softc *sc, uint32_t idx,
    uint32_t tag, uint32_t mask, uint32_t action)
{
	int error;

	AQ_MPI_LOCK(sc);

	WAIT_FOR(AQ_READ_REG(sc, AQ2_ART_SEM_REG) == 1, 10, 1000, &error);
	if (error != 0) {
		printf("%s: AQ2_ART_SEM_REG timeout\n", DEVNAME(sc));
		goto out;
	}

	idx += sc->sc_art_filter_base_index;
	AQ_WRITE_REG(sc, AQ2_RPF_ACT_ART_REQ_TAG_REG(idx), tag);
	AQ_WRITE_REG(sc, AQ2_RPF_ACT_ART_REQ_MASK_REG(idx), mask);
	AQ_WRITE_REG(sc, AQ2_RPF_ACT_ART_REQ_ACTION_REG(idx), action);

	AQ_WRITE_REG(sc, AQ2_ART_SEM_REG, 1);

 out:
	AQ_MPI_UNLOCK(sc);
	return error;
}

/*
 * Update interface filter flags (promiscuous/multicast).
 * Called when IFF_PROMISC or the multicast list changes.
 *
 * Three modes:
 *   1. Promiscuous: accept all packets (disable ART drop rules on AQ2)
 *   2. All-multicast: too many multicast addrs or ranges; use HW filter
 *   3. Normal: program individual multicast addresses into HW MAC filters
 *      (up to AQ_HW_MAC_NUM entries; index 0 is the primary MAC)
 */
void
aq_iff(struct aq_softc *sc)
{
	struct ifnet *ifp = &sc->sc_arpcom.ac_if;
	struct arpcom *ac = &sc->sc_arpcom;
	struct ether_multi *enm;
	struct ether_multistep step;
	uint32_t action;
	int idx;

	if (HWTYPE_AQ2_P(sc)) {
		action = (ifp->if_flags & IFF_PROMISC) ?
		    AQ2_ART_ACTION_DISABLE : AQ2_ART_ACTION_DROP;
		aq2_filter_art_set(sc, AQ2_RPF_INDEX_L2_PROMISC_OFF, 0,
		    AQ2_RPF_TAG_UC_MASK | AQ2_RPF_TAG_ALLMC_MASK, action);
		aq2_filter_art_set(sc, AQ2_RPF_INDEX_VLAN_PROMISC_OFF, 0,
		    AQ2_RPF_TAG_VLAN_MASK | AQ2_RPF_TAG_UNTAG_MASK, action);
	}

	if (ifp->if_flags & IFF_PROMISC) {
		ifp->if_flags |= IFF_ALLMULTI;
		AQ_WRITE_REG_BIT(sc, RPF_L2BC_REG, RPF_L2BC_PROMISC, 1);
	} else if (ac->ac_multirangecnt > 0 ||
	    ac->ac_multicnt >= AQ_HW_MAC_NUM) {
		ifp->if_flags |= IFF_ALLMULTI;
		AQ_WRITE_REG_BIT(sc, RPF_L2BC_REG, RPF_L2BC_PROMISC, 0);
		AQ_WRITE_REG_BIT(sc, RPF_MCAST_FILTER_MASK_REG,
		    RPF_MCAST_FILTER_MASK_ALLMULTI, 1);
		AQ_WRITE_REG_BIT(sc, RPF_MCAST_FILTER_REG(0),
		    RPF_MCAST_FILTER_EN, 1);
	} else {
		ifp->if_flags &= ~IFF_ALLMULTI;
		idx = AQ_HW_MAC_OWN + 1;

		AQ_WRITE_REG_BIT(sc, RPF_L2BC_REG, RPF_L2BC_PROMISC, 0);

		ETHER_FIRST_MULTI(step, ac, enm);
		while (enm != NULL) {
			aq_set_mac_addr(sc, idx++, enm->enm_addrlo);
			ETHER_NEXT_MULTI(step, enm);
		}

		for (; idx < AQ_HW_MAC_NUM; idx++)
			aq_set_mac_addr(sc, idx, NULL);

		AQ_WRITE_REG_BIT(sc, RPF_MCAST_FILTER_MASK_REG,
		    RPF_MCAST_FILTER_MASK_ALLMULTI, 0);
		AQ_WRITE_REG_BIT(sc, RPF_MCAST_FILTER_REG(0),
		    RPF_MCAST_FILTER_EN, 0);
	}
}

/*
 * Wait for an SMBus transaction to complete.
 * Used by aq_get_sffpage() for SFP/SFP+ module access on fibre variants.
 */
int
aq_smb_bus_wait_result(struct aq_softc *sc, int ack)
{
	int error;

	WAIT_FOR(
	    (AQ_READ_REG(sc, AQ_SMB_BUS_REG) & AQ_SMB_BUS_XFER_COMPLETE) != 0,
	    100, 10000, &error);
	if (error != 0)
		return error;
	if ((AQ_READ_REG(sc, AQ_SMB_BUS_REG) & AQ_SMB_BUS_RX_ACK) != ack)
		return EIO;
	return 0;
}

/*
 * Read a page of data from an SFP/SFP+ transceiver module via SMBus.
 * Implements the I2C read protocol: START, write address, REPEAT START,
 * read 256 bytes of data, NACK last byte, STOP.  Used by the
 * SIOCGIFSFFPAGE ioctl for "ifconfig aq0 sff" SFP diagnostics.
 */
int
aq_get_sffpage(struct aq_softc *sc, struct if_sffpage *sff)
{
	int error;
	int i;

	WAIT_FOR((AQ_READ_REG(sc, AQ_SMB_BUS_REG) & AQ_SMB_BUS_BUSY) == 0,
	    10, 1000, &error);
	if (error != 0) {
		printf("%s: AQ_SMB_BUS_BUSY timeout\n", DEVNAME(sc));
		return error;
	}

	AQ_WRITE_REG(sc, AQ_SMB_TX_DATA_REG, sff->sff_addr);
	AQ_WRITE_REG(sc, AQ_SMB_PROVISIONING_REG, AQ_SMB_START_TRANSMIT);
	error = aq_smb_bus_wait_result(sc, 0);
	if (error != 0) {
		printf("%s: AQ_SMB_START_TRANSMIT timeout\n", DEVNAME(sc));
		goto out;
	}

	AQ_WRITE_REG(sc, AQ_SMB_TX_DATA_REG, 0);
	AQ_WRITE_REG(sc, AQ_SMB_PROVISIONING_REG, AQ_SMB_REPEAT_TRANSMIT);
	error = aq_smb_bus_wait_result(sc, 0);
	if (error != 0) {
		printf("%s: AQ_SMB_REPEAT_TRANSMIT timeout\n", DEVNAME(sc));
		goto out;
	}

	AQ_WRITE_REG(sc, AQ_SMB_TX_DATA_REG, sff->sff_addr | 1);
	AQ_WRITE_REG(sc, AQ_SMB_PROVISIONING_REG, AQ_SMB_START_READ_TRANSMIT);
	error = aq_smb_bus_wait_result(sc, 0);
	if (error != 0) {
		printf("%s: AQ_SMB_START_READ_TRANSMIT timeout\n", DEVNAME(sc));
		goto out;
	}
	if ((AQ_READ_REG(sc, AQ_SMB_BUS_REG) & AQ_SMB_BUS_REPEAT_DETECT) == 0) {
		error = EIO;
		goto out;
	}

	for (i = 0; i < sizeof(sff->sff_data)-1; i++) {
		AQ_WRITE_REG(sc, AQ_SMB_PROVISIONING_REG,
		    AQ_SMB_REPEAT_TRANSMIT);
		error = aq_smb_bus_wait_result(sc, 0);
		if (error != 0) {
			printf("%s: AQ_SMB_REPEAT_TRANSMIT %d timeout\n",
			    DEVNAME(sc), i);
			goto out;
		}

		sff->sff_data[i] = AQ_READ_REG(sc, AQ_SMB_RX_DATA_REG);
	}

	AQ_WRITE_REG(sc, AQ_SMB_PROVISIONING_REG, AQ_SMB_REPEAT_NACK_TRANSMIT);
	error = aq_smb_bus_wait_result(sc, AQ_SMB_BUS_RX_ACK);
	if (error != 0) {
		printf("%s: AQ_SMB_REPEAT_NACK_TRANSMIT failed\n", DEVNAME(sc));
	}
	sff->sff_data[i] = AQ_READ_REG(sc, AQ_SMB_RX_DATA_REG);

 out:
	AQ_WRITE_REG(sc, AQ_SMB_PROVISIONING_REG, AQ_SMB_STOP_TRANSMIT);
	return error;
}

/*
 * Allocate a contiguous DMA-accessible memory region.
 * Used for TX/RX descriptor rings.  Performs the full bus_dma(9)
 * allocation sequence: create map -> alloc memory -> map to KVA -> load.
 * On failure at any step, unwinds the partial allocation.
 */
int
aq_dmamem_alloc(struct aq_softc *sc, struct aq_dmamem *aqm,
    bus_size_t size, u_int align)
{
	aqm->aqm_size = size;

	if (bus_dmamap_create(sc->sc_dmat, aqm->aqm_size, 1,
	    aqm->aqm_size, 0,
	    BUS_DMA_WAITOK | BUS_DMA_ALLOCNOW | BUS_DMA_64BIT,
	    &aqm->aqm_map) != 0)
		return (1);
	if (bus_dmamem_alloc(sc->sc_dmat, aqm->aqm_size,
	    align, 0, &aqm->aqm_seg, 1, &aqm->aqm_nsegs,
	    BUS_DMA_WAITOK | BUS_DMA_ZERO) != 0)
		goto destroy;
	if (bus_dmamem_map(sc->sc_dmat, &aqm->aqm_seg, aqm->aqm_nsegs,
	    aqm->aqm_size, &aqm->aqm_kva,
	    BUS_DMA_WAITOK | BUS_DMA_COHERENT) != 0)
		goto free;
	if (bus_dmamap_load(sc->sc_dmat, aqm->aqm_map, aqm->aqm_kva,
	    aqm->aqm_size, NULL, BUS_DMA_WAITOK) != 0)
		goto unmap;

	return (0);
unmap:
	bus_dmamem_unmap(sc->sc_dmat, aqm->aqm_kva, aqm->aqm_size);
free:
	bus_dmamem_free(sc->sc_dmat, &aqm->aqm_seg, 1);
destroy:
	bus_dmamap_destroy(sc->sc_dmat, aqm->aqm_map);
	return (1);
}

/* Free a DMA memory region (reverse of aq_dmamem_alloc). */
void
aq_dmamem_free(struct aq_softc *sc, struct aq_dmamem *aqm)
{
	bus_dmamap_unload(sc->sc_dmat, aqm->aqm_map);
	bus_dmamem_unmap(sc->sc_dmat, aqm->aqm_kva, aqm->aqm_size);
	bus_dmamem_free(sc->sc_dmat, &aqm->aqm_seg, 1);
	bus_dmamap_destroy(sc->sc_dmat, aqm->aqm_map);
}
