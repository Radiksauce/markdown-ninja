<template>
  <div>
    <div class="rounded-md bg-red-50 p-4 mb-3" v-if="error">
      <div class="flex">
        <div class="ml-3">
          <p class="text-sm text-red-700">
            {{ error }}
          </p>
        </div>
      </div>
    </div>

    <div class="mb-3">
      <!-- <b>1 email / week to learn how to (ab)use technology for fun & profit: Programming, Hacking & Entrepreneurship. It's free :)</b> -->
      <!-- <b>1 email / week to learn how to build secure and scalable software systems. It's free :)</b> -->
       <b>Join the newsletter to get the latest updates</b>
    </div>

    <div>
      <!-- <label for="email" class="block text-sm font-medium text-gray-700">
        Subscribe
      </label> -->
      <div>
        <input id="email" ref="subscribeInput" name="email" type="email" autocomplete="email" required placeholder="my@email.com"
          v-model="email" @keyup="lowercaseEmail" autofocus
          class="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-xs
          placeholder-gray-400 focus:outline-hidden focus:ring-[var(--mdninja-accent)]
              focus:border-[var(--mdninja-accent)] sm:text-sm" />
      </div>
    </div>


    <div class="flex items-center justify-between mt-3">
      <div class="text-sm">
        Already have an account?
        <PLink class="font-medium" href="/account/login">
          Log in here!
        </PLink>
      </div>
    </div>

    <div class="mt-3">
      <PButton :loading="loading" @click="onSubscribeClicked()">
        Subscribe
      </PButton>
    </div>



    <div class="mt-1.5">
      <small>
        No spam ever, unsubscribe anytime and we will never share your email.
        You can also grab
        <a target="_blank" href="https://kerkour.com/feed.xml">the RSS feed</a>
      </small>
    </div>
  </div>
</template>

<script lang="ts" setup>
import { onMounted, ref, type Ref } from 'vue';
import PButton from '@/ui/components/p_button.vue';
import type { SubscribeInput } from '@/app/model';
import PLink from '@/ui/components/p_link.vue';
import { subscribe } from '@/app/mdninja';

// props

// events
const $emit = defineEmits(['created']);

// composables

// lifecycle
onMounted(() => {
  subscribeInput.value?.focus();
  subscribeInput.value?.scrollIntoView();
})

// variables
let loading = ref(false);
let error = ref('');
let email = ref('');
const subscribeInput: Ref<HTMLElement | null> = ref(null);


// computed

// watch

// functions
function lowercaseEmail() {
  email.value = email.value.toLowerCase();
}

async function onSubscribeClicked() {
  loading.value = true;
  error.value = '';
  const input: SubscribeInput = {
    email: email.value,
  };

  try {
    const res = await subscribe(input);
    $emit('created', res.contact_id);
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>
