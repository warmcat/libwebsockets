#include "webcam-media.h"

#if defined(LWS_WITH_MEDIA_RK_MPI)

#include <string.h>
#include <unistd.h>
#include <rk_debug.h>
#include <rk_defines.h>
#include <rk_mpi_sys.h>
#include <rk_mpi_vi.h>
#include <rk_mpi_venc.h>
#include <rk_mpi_mb.h>

/* uClibc shim */
#include <ctype.h>
#include <stdio.h>
__attribute__((visibility("default"))) const unsigned short *__ctype_b;
__attribute__((constructor)) void init_uclibc_shims(void) { __ctype_b = *__ctype_b_loc(); }
__attribute__((visibility("default"))) int __fputc_unlocked(int c, FILE *stream) { return fputc_unlocked(c, stream); }

static int chnId = 0;

static int media_rkmpi_init(struct pss_camshow *pss) {
	VI_DEV_ATTR_S stDevAttr;
	VI_DEV_BIND_PIPE_S stBindPipe;
	VI_CHN_ATTR_S vi_chn_attr;
	VENC_CHN_ATTR_S stVencAttr;
	MPP_CHN_S stSrcChn, stDestChn;

	if (RK_MPI_SYS_Init() != RK_SUCCESS)
		return -1;

	// VI Dev 0 init
	memset(&stDevAttr, 0, sizeof(stDevAttr));
	memset(&stBindPipe, 0, sizeof(stBindPipe));
	if (RK_MPI_VI_GetDevAttr(0, &stDevAttr) == RK_ERR_VI_NOT_CONFIG) {
		if (RK_MPI_VI_SetDevAttr(0, &stDevAttr) != RK_SUCCESS) return -1;
	}
	if (RK_MPI_VI_GetDevIsEnable(0) != RK_SUCCESS) {
		if (RK_MPI_VI_EnableDev(0) != RK_SUCCESS) return -1;
		stBindPipe.u32Num = 1;
		stBindPipe.PipeId[0] = 0;
		if (RK_MPI_VI_SetDevBindPipe(0, &stBindPipe) != RK_SUCCESS) return -1;
	}

	// VI Chn init
	memset(&vi_chn_attr, 0, sizeof(vi_chn_attr));
	vi_chn_attr.stIspOpt.u32BufCount = 2;
	vi_chn_attr.stIspOpt.enMemoryType = VI_V4L2_MEMORY_TYPE_DMABUF;
	vi_chn_attr.stSize.u32Width = pss->target_width;
	vi_chn_attr.stSize.u32Height = pss->target_height;
	vi_chn_attr.enPixelFormat = RK_FMT_YUV420SP;
	vi_chn_attr.enCompressMode = COMPRESS_MODE_NONE;
	if (RK_MPI_VI_SetChnAttr(0, chnId, &vi_chn_attr) != RK_SUCCESS) return -1;
	if (RK_MPI_VI_EnableChn(0, chnId) != RK_SUCCESS) return -1;

	// VENC init
	memset(&stVencAttr, 0, sizeof(stVencAttr));
	stVencAttr.stRcAttr.enRcMode = VENC_RC_MODE_H264CBR;
	stVencAttr.stRcAttr.stH264Cbr.u32BitRate = 1000 * 1024;
	stVencAttr.stRcAttr.stH264Cbr.u32Gop = 30;

	stVencAttr.stVencAttr.enType = RK_VIDEO_ID_AVC;
	stVencAttr.stVencAttr.enPixelFormat = RK_FMT_YUV420SP;
	stVencAttr.stVencAttr.u32Profile = H264E_PROFILE_HIGH;
	stVencAttr.stVencAttr.u32PicWidth = pss->target_width;
	stVencAttr.stVencAttr.u32PicHeight = pss->target_height;
	stVencAttr.stVencAttr.u32VirWidth = pss->target_width;
	stVencAttr.stVencAttr.u32VirHeight = pss->target_height;
	stVencAttr.stVencAttr.u32StreamBufCnt = 2;
	stVencAttr.stVencAttr.u32BufSize = pss->target_width * pss->target_height * 3 / 2;
	stVencAttr.stVencAttr.enMirror = MIRROR_NONE;

	if (RK_MPI_VENC_CreateChn(chnId, &stVencAttr) != RK_SUCCESS) return -1;

	VENC_RECV_PIC_PARAM_S stRecvParam;
	memset(&stRecvParam, 0, sizeof(stRecvParam));
	stRecvParam.s32RecvPicNum = -1;
	if (RK_MPI_VENC_StartRecvFrame(chnId, &stRecvParam) != RK_SUCCESS) return -1;

	// Bind VI -> VENC
	stSrcChn.enModId = RK_ID_VI;
	stSrcChn.s32DevId = 0;
	stSrcChn.s32ChnId = chnId;

	stDestChn.enModId = RK_ID_VENC;
	stDestChn.s32DevId = 0;
	stDestChn.s32ChnId = chnId;
	if (RK_MPI_SYS_Bind(&stSrcChn, &stDestChn) != RK_SUCCESS) return -1;

	return 0;
}

static int media_rkmpi_get_event_fd(struct pss_camshow *pss) {
	return RK_MPI_VENC_GetFd(chnId);
}

static int media_rkmpi_process_rx(struct pss_camshow *pss) {
	VENC_STREAM_S stFrame;
	memset(&stFrame, 0, sizeof(stFrame));
	stFrame.pstPack = malloc(sizeof(VENC_PACK_S));

	if (RK_MPI_VENC_GetStream(chnId, &stFrame, 0) == RK_SUCCESS) {
		if (stFrame.pstPack->u32Len > 0) {
			void *pData = RK_MPI_MB_Handle2VirAddr(stFrame.pstPack->pMbBlk);
			if (we_ops && we_ops->send_video && pss->pss) {
				we_ops->send_video(we_ops->get_media((struct pss_webrtc *)pss->pss),
								   pData, stFrame.pstPack->u32Len,
								   LWS_WEBRTC_CODEC_H264,
								   (uint32_t)(lws_now_usecs() * 9 / 100));
				pss->packets_sent++;
			}
		}
		RK_MPI_VENC_ReleaseStream(chnId, &stFrame);
	}
	free(stFrame.pstPack);
	return 0;
}

static int media_rkmpi_send_caps(struct pss_camshow *pss) {
	const char *rep = "{\"type\":\"capabilities\",\"kind\":\"video\",\"controls\":[]}";
	if (we_ops && we_ops->send_text)
		we_ops->send_text(pss->pss, rep, strlen(rep));
	return 0;
}

static int media_rkmpi_set_control(struct pss_camshow *pss, uint32_t id, int32_t val) {
	return 0;
}

static void media_rkmpi_deinit(struct pss_camshow *pss) {
	MPP_CHN_S stSrcChn, stDestChn;
	stSrcChn.enModId = RK_ID_VI;
	stSrcChn.s32DevId = 0;
	stSrcChn.s32ChnId = chnId;
	stDestChn.enModId = RK_ID_VENC;
	stDestChn.s32DevId = 0;
	stDestChn.s32ChnId = chnId;

	RK_MPI_SYS_UnBind(&stSrcChn, &stDestChn);
	RK_MPI_VENC_StopRecvFrame(chnId);
	RK_MPI_VENC_DestroyChn(chnId);
	RK_MPI_VI_DisableChn(0, chnId);
	RK_MPI_SYS_Exit();
}

const struct lws_cam_pipeline_ops pipeline_rk_mpi = {
	.name = "rk_mpi",
	.init = media_rkmpi_init,
	.get_event_fd = media_rkmpi_get_event_fd,
	.process_rx = media_rkmpi_process_rx,
	.send_capabilities = media_rkmpi_send_caps,
	.set_control = media_rkmpi_set_control,
	.deinit = media_rkmpi_deinit,
};

#endif
