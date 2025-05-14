<template>
  <div v-for="[year, posts] in postsByYear">
    <h1 class="text-3xl">{{ year }}</h1>
    <ul class="px-0 mx-0">
      <li class="flex flex-col" v-for="(post, _index) in posts" :key="post.path">
        <RouterLink :to="post.path" class="mdninja-post-link text-(--mdninja-text) py-4 rounded-[4px] text-md w-full no-underline px-2 flex flex-col sm:flex-row justify-between">
          <span class="flex text-(--mdninja-text)">{{ post.title }}</span>
          <span class="flex pt-3 sm:pt-0 sm:pl-3 min-w-max">
            <time :datetime="date(post.date)" class="text-(--mdninja-text) opacity-50 text-lg">
              {{ date(post.date, false) }}
            </time>
          </span>
        </RouterLink>
      </li>
    </ul>
  </div>

  <!-- <ul class="px-0 mx-0">
      <li class="flex flex-col" v-for="(post, $index) in posts" :key="post.path">
        <RouterLink :to="post.path" class="py-4 rounded-[4px] text-lg hover:bg-[#f5f5f5] w-full hover:no-underline px-3 flex flex-col sm:flex-row justify-between">
          <span class="flex">{{ post.title }}</span>
          <span class="flex pt-3 sm:pt-0 sm:pl-3 min-w-max">
            <time :datetime="date(post.date)" class="text-[#8f8f8f] text-lg">
              {{ date(post.date, false) }}
            </time>
          </span>
        </RouterLink>
        <hr v-if="$index !== posts.length - 1" />
      </li>
  </ul> -->
</template>

<script lang="ts" setup>
import date from '@/libs/date';
import type { PageMetadata } from '@/app/model';
import { computed, type PropType } from 'vue';

// props
const props = defineProps({
  posts: {
    type: Array as PropType<PageMetadata[]>,
    required: true,
  },
});

// events

// composables

// lifecycle
const postsByYear = computed(() => {
  const postsByYear = new Map<string, PageMetadata[]>();
  for (let post of props.posts) {
    let year = new Date(post.date).getUTCFullYear().toString();
    let postsForYear = postsByYear.get(year) ?? [];
    postsByYear.set(year, [...postsForYear, post]);
  }
  return postsByYear;
});

// variables

// computed

// watch

// functions
</script>

<style scoped>
/* .mdninja-post-link:hover {

} */
.mdninja-post-link:hover {
  background-color: color-mix(in srgb, var(--mdninja-accent), transparent 95%);
  /* background-color: rgb(from var(--mdninja-accent) r g b / 12%); */
}

</style>
