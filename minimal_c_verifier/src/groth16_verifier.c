#include "groth16_verifier.h"
#include "vk_constants.h"

/* L = IC[0] + sum_i public_input[i] * IC[i+1] */
static int prepare_inputs(ep_t L, const groth16_vk_t *vk, const uint8_t *pi_buf) {
    ep_t ic, tmp;
    bn_t scalar;
    int ret = -1;

    ep_null(ic); ep_null(tmp);
    bn_null(scalar);
    ep_new(ic); ep_new(tmp);
    bn_new(scalar);

    if (decode_g1(L, vk->ic) != 0) goto out;

    for (size_t i = 0; i < vk->num_public_inputs; i++) {
        if (decode_g1(ic, vk->ic + (i + 1) * 64) != 0) goto out;
        if (decode_fr(scalar, pi_buf + i * 32) != 0) goto out;
        ep_mul(tmp, ic, scalar);
        ep_add(L, L, tmp);
    }
    ep_norm(L, L);
    ret = 0;

out:
    ep_free(ic); ep_free(tmp);
    bn_free(scalar);
    return ret;
}

int groth16_verify_vk(
    const groth16_vk_t *vk,
    const uint8_t *proof_buf,
    size_t         proof_len,
    const uint8_t *public_input_buf,
    size_t         pi_len
) {
    if (proof_len != 256 || pi_len != vk->num_public_inputs * 32) {
        return -1;
    }

    ep_t A, C, L;
    ep2_t B, neg_gamma, neg_delta;
    fp12_t result, cached_ab;

    ep_null(A); ep_null(C); ep_null(L);
    ep2_null(B); ep2_null(neg_gamma); ep2_null(neg_delta);
    fp12_null(result); fp12_null(cached_ab);

    ep_new(A); ep_new(C); ep_new(L);
    ep2_new(B); ep2_new(neg_gamma); ep2_new(neg_delta);
    fp12_new(result); fp12_new(cached_ab);

    int ret = -1;

    if (decode_g1(A, proof_buf) != 0) goto cleanup;
    if (decode_g2(B, proof_buf + 64) != 0) goto cleanup;
    if (decode_g1(C, proof_buf + 192) != 0) goto cleanup;

    if (decode_g2(neg_gamma, vk->neg_gamma) != 0) goto cleanup;
    if (decode_g2(neg_delta, vk->neg_delta) != 0) goto cleanup;
    if (decode_gt(cached_ab, vk->alpha_beta) != 0) goto cleanup;

    if (prepare_inputs(L, vk, public_input_buf) != 0) goto cleanup;

    /* Multi-pairing: e(A,B) * e(L,-gamma) * e(C,-delta) */
    ep_t p_arr[3];
    ep2_t q_arr[3];
    ep_null(p_arr[0]); ep_null(p_arr[1]); ep_null(p_arr[2]);
    ep2_null(q_arr[0]); ep2_null(q_arr[1]); ep2_null(q_arr[2]);
    ep_new(p_arr[0]); ep_new(p_arr[1]); ep_new(p_arr[2]);
    ep2_new(q_arr[0]); ep2_new(q_arr[1]); ep2_new(q_arr[2]);

    ep_copy(p_arr[0], A);
    ep_copy(p_arr[1], L);
    ep_copy(p_arr[2], C);
    ep2_copy(q_arr[0], B);
    ep2_copy(q_arr[1], neg_gamma);
    ep2_copy(q_arr[2], neg_delta);

    pp_map_sim_k12(result, p_arr, q_arr, 3);

    ret = (fp12_cmp(result, cached_ab) == RLC_EQ) ? 1 : 0;

    ep_free(p_arr[0]); ep_free(p_arr[1]); ep_free(p_arr[2]);
    ep2_free(q_arr[0]); ep2_free(q_arr[1]); ep2_free(q_arr[2]);

cleanup:
    ep_free(A); ep_free(C); ep_free(L);
    ep2_free(B); ep2_free(neg_gamma); ep2_free(neg_delta);
    fp12_free(result); fp12_free(cached_ab);
    return ret;
}

int groth16_verify(
    const uint8_t *proof_buf,
    size_t         proof_len,
    const uint8_t *public_input_buf,
    size_t         pi_len
) {
    /* IC[0] and IC[1] are separate 64-byte arrays in vk_constants.h; the
     * generalized path expects them contiguous. */
    static uint8_t ic_flat[128];
    static int ic_ready = 0;
    if (!ic_ready) {
        for (int i = 0; i < 64; i++) ic_flat[i] = VK_IC0_G1[i];
        for (int i = 0; i < 64; i++) ic_flat[64 + i] = VK_IC1_G1[i];
        ic_ready = 1;
    }

    const groth16_vk_t vk = {
        .ic = ic_flat,
        .num_public_inputs = GROTH16_NUM_PUBLIC_INPUTS,
        .alpha_beta = VK_ALPHA_BETA_GT,
        .neg_gamma = VK_NEG_GAMMA_G2,
        .neg_delta = VK_NEG_DELTA_G2,
    };
    return groth16_verify_vk(&vk, proof_buf, proof_len, public_input_buf, pi_len);
}
