<template>
  <div>
    <article class="flex flex-col">
      <h1 class="text-center font-semibold">{{  page.title }}</h1>

      <span class="text-center text-[#8f8f8f] my-2 font-medium">
        <time :datetime="date(page.date)">{{ date(page.date, false) }}</time>
      </span>

      <!-- <div v-html="page.body" /> -->
      <Phtml :html="page.body" />
    </article>

    <div v-if="page.tags.length !== 0" class="my-5">
      <strong class="mx-2">Tags:&nbsp;</strong>
      <!-- <span  class=""> -->
        <!-- <span v-if="$index !== 0">, </span> -->
        <RouterLink  v-for="(tag, _index) in page.tags" :key="tag.name" :to="tagUrl(tag)"
          class="mr-2"
        >
          <span class="inline-flex items-center gap-x-1.5 rounded-md px-2 py-1 font-medium text-[var(--mdninja-accent)] ring-1 ring-inset ring-gray-200 hover:ring-[var(--mdninja-accent)]">
            {{ tag.name }}
          </span>
        </RouterLink>
      <!-- </span> -->
    </div>

    <hr class="my-4" v-if="!$store.contact" />
    <SubscribeFormInline v-if="!$store.contact" />

  </div>
</template>

<script lang="ts" setup>
import date from '@/libs/date';
import type { Page, Tag } from '@/app/model';
import type { PropType } from 'vue';
import SubscribeFormInline from '@/ui/components/subscribe_form_inline.vue';
import Phtml from '@/ui/components/p_html.vue';
import { useStore } from '@/app/store';

// props
defineProps({
  page: {
    type: Object as PropType<Page>,
    required: true,
  },
});

// events

// composables
const $store = useStore();

// lifecycle

// variables

// computed

// watch

// functions
function tagUrl(tag: Tag) {
  return `/tags/${tag.name}`;
}
</script>
