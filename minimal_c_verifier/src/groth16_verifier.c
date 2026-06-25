#include "groth16_verifier.h"
#include "vk_constants.h"

static int prepare_inputs(ep_t L, const uint8_t *pi_buf) {
    ep_t ic0, ic1, tmp;
    bn_t scalar;

    ep_null(ic0); ep_null(ic1); ep_null(tmp);
    bn_null(scalar);
    ep_new(ic0); ep_new(ic1); ep_new(tmp);
    bn_new(scalar);

    if (decode_g1(ic0, VK_IC0_G1) != 0) goto err;
    if (decode_g1(ic1, VK_IC1_G1) != 0) goto err;
    if (decode_fr(scalar, pi_buf) != 0) goto err;

    ep_mul(tmp, ic1, scalar);
    ep_add(L, ic0, tmp);
    ep_norm(L, L);

    ep_free(ic0); ep_free(ic1); ep_free(tmp);
    bn_free(scalar);
    return 0;

err:
    ep_free(ic0); ep_free(ic1); ep_free(tmp);
    bn_free(scalar);
    return -1;
}

int groth16_verify(
    const uint8_t *proof_buf,
    size_t         proof_len,
    const uint8_t *public_input_buf,
    size_t         pi_len
) {
    if (proof_len != 256 || pi_len != 32) {
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

    if (decode_g2(neg_gamma, VK_NEG_GAMMA_G2) != 0) goto cleanup;
    if (decode_g2(neg_delta, VK_NEG_DELTA_G2) != 0) goto cleanup;
    if (decode_gt(cached_ab, VK_ALPHA_BETA_GT) != 0) goto cleanup;

    if (prepare_inputs(L, public_input_buf) != 0) goto cleanup;

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
