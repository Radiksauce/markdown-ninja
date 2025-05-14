<template>
  <div class="flex ml-3 rounded-md bg-red-50 p-4" v-if="error">
    <p class="text-sm text-red-700">
      {{ error }}
    </p>
  </div>
</template>

<script lang="ts" setup>

import { useMdninja } from '@/api/mdninja';
import { usePingoo } from '@/pingoo/pingoo';
import { onBeforeMount, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';

// The auth page is our OIDC auth callback. Its purpose to handle authentication-related flows.

// props

// events

// composables
const $pingoo = usePingoo();
const $router = useRouter();
const $route = useRoute();
const $mdninja = useMdninja();

// lifecycle
onBeforeMount(async () => handleAuth());

// variables
let error = ref('');

// computed

// watch

// functions
async function handleAuth() {
  if (Object.keys($route.query).length === 0) {
    $router.push('/');
    return;
  }

  try {
    await $pingoo.handleSignInCallback(window.location.href);
    $router.replace({ query: {}});
    await $mdninja.init();
    // when using router, this does not reload the state of the app
    $router.push('/organizations');
    // window.location.href = '/organizations';
  } catch (err: any) {
    error.value = err.message
  }
}
</script>
