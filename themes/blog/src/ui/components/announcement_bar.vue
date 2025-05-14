<template>
  <div v-if="showAnnouncement"
    class="w-full flex bg-[var(--mdninja-accent)] items-center gap-x-6 px-6 py-2.5 sm:px-3.5 sm:before:flex-1">

    <div v-html="$store.website!.announcement"
      class="mdninja-announcement-bar text-sm/6 text-[var(--mdninja-background)]" />

    <div class="flex flex-1 justify-end">
      <button type="button" @click="hide()"
        class="-m-2 p-2 shadow-none focus-visible:outline-offset-[-4px] bg-[var(--mdninja-accent)] hover:brightness-[0.95]">
        <span class="sr-only">Close</span>
        <XMarkIcon class="h-5 w-5" aria-hidden="true" />
      </button>
    </div>
  </div>
</template>

<script lang="ts" setup>
import { useStore } from '@/app/store';
import { hashSha512 } from '@/libs/crypto';
import { XMarkIcon } from '@heroicons/vue/20/solid';
import { onBeforeMount, ref } from 'vue';

type SavedAnnouncementPreferences = {
  announcementHash: string;
  hiddenAt: string;
};

const PREFERENCES_STORAGE_KEY = '__markdown_ninja_announcement_preferences';

// props

// events

// composables
const $store = useStore();

// lifecycle
onBeforeMount(async () => {
  // show the announcement if there is not stored hash or if the hash is different than the hash of the current announcement
  if ($store.website?.announcement) {
      const announcementPreferencesStr = localStorage.getItem(PREFERENCES_STORAGE_KEY);
      if (announcementPreferencesStr) {
      try {
        let announcementPreferences: SavedAnnouncementPreferences = JSON.parse(announcementPreferencesStr);
        const announcementHash = await hashSha512(new TextEncoder().encode($store.website.announcement));
        // Unix timestamp for 30 days agos
        const thirtyDaysAgo = (new Date().getTime() / 1000) - (30 * 24 * 3600);
        // Unix timestamp for when the announcement was last closed
        const announcementClosedAt = new Date(announcementPreferences.hiddenAt).getTime() / 1000;

        if (announcementPreferences.announcementHash !== announcementHash || announcementClosedAt <= thirtyDaysAgo) {
          showAnnouncement.value = true;
        }
      } catch (err) {
        console.error(err);
        return;
      }
    } else {
      showAnnouncement.value = true;
    }
  }
})

// variables
let showAnnouncement = ref(false);

// computed

// watch

// functions
async function hide() {
  if (!$store.website?.announcement) {
    return;
  }
  // we first need to save the value of the announcement because the call to the store mutation will
  // modify it
  const announcementValue = $store.website.announcement;

  showAnnouncement.value = false;

  try {
    const announcementHash = await hashSha512(new TextEncoder().encode(announcementValue));
    let preferences: SavedAnnouncementPreferences = {
      announcementHash: announcementHash,
      hiddenAt: new Date().toISOString(),
    };
    localStorage.setItem(PREFERENCES_STORAGE_KEY, JSON.stringify(preferences));
  } catch (err) {
    console.error(err);
    return;
  }
}
</script>

<style lang="css">
.mdninja-announcement-bar > a {
  color: var(--mdninja-background);
  text-decoration: underline;
}
</style>
