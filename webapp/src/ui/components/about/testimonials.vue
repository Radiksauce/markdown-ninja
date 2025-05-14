<template>
    <!-- <div class="pb-20 sm:pb-24 md:pb-0">
      <div class="mx-auto flex max-w-7xl flex-col items-center gap-x-8 gap-y-10 px-6 sm:gap-y-8 md:px-8 md:flex-row items-stretch">
        <div class="-mt-8 w-full max-w-2xl md:-mb-8 md:w-96 md:flex-none">
          <div class="relative aspect-[2/1] h-full md:-mx-8 md:mx-0 md:aspect-auto">
            <a href="https://kerkour.com/black-hat-rust" target="_blank" rel="noopener">
              <img  src="/webapp/about/black_hat_rust_cover.svg" alt="Black Hat Rust cover"
                class="absolute inset-0 h-full w-full rounded-2xl bg-gray-800 object-cover shadow-2xl"
              />
            </a>
          </div>
        </div>
        <div class="w-full max-w-2xl md:max-w-none md:flex-auto md:px-16 md:py-24 font-base">
          <figure class="relative isolate pt-6 sm:pt-12">
            <svg viewBox="0 0 162 128" fill="none" aria-hidden="true" class="absolute left-0 top-0 -z-10 h-32 stroke-(--primary-color)/15">
              <path id="b56e9dab-6ccb-4d32-ad02-6b4bb5d9bbeb" d="M65.5697 118.507L65.8918 118.89C68.9503 116.314 71.367 113.253 73.1386 109.71C74.9162 106.155 75.8027 102.28 75.8027 98.0919C75.8027 94.237 75.16 90.6155 73.8708 87.2314C72.5851 83.8565 70.8137 80.9533 68.553 78.5292C66.4529 76.1079 63.9476 74.2482 61.0407 72.9536C58.2795 71.4949 55.276 70.767 52.0386 70.767C48.9935 70.767 46.4686 71.1668 44.4872 71.9924L44.4799 71.9955L44.4726 71.9988C42.7101 72.7999 41.1035 73.6831 39.6544 74.6492C38.2407 75.5916 36.8279 76.455 35.4159 77.2394L35.4047 77.2457L35.3938 77.2525C34.2318 77.9787 32.6713 78.3634 30.6736 78.3634C29.0405 78.3634 27.5131 77.2868 26.1274 74.8257C24.7483 72.2185 24.0519 69.2166 24.0519 65.8071C24.0519 60.0311 25.3782 54.4081 28.0373 48.9335C30.703 43.4454 34.3114 38.345 38.8667 33.6325C43.5812 28.761 49.0045 24.5159 55.1389 20.8979C60.1667 18.0071 65.4966 15.6179 71.1291 13.7305C73.8626 12.8145 75.8027 10.2968 75.8027 7.38572C75.8027 3.6497 72.6341 0.62247 68.8814 1.1527C61.1635 2.2432 53.7398 4.41426 46.6119 7.66522C37.5369 11.6459 29.5729 17.0612 22.7236 23.9105C16.0322 30.6019 10.618 38.4859 6.47981 47.558L6.47976 47.558L6.47682 47.5647C2.4901 56.6544 0.5 66.6148 0.5 77.4391C0.5 84.2996 1.61702 90.7679 3.85425 96.8404L3.8558 96.8445C6.08991 102.749 9.12394 108.02 12.959 112.654L12.959 112.654L12.9646 112.661C16.8027 117.138 21.2829 120.739 26.4034 123.459L26.4033 123.459L26.4144 123.465C31.5505 126.033 37.0873 127.316 43.0178 127.316C47.5035 127.316 51.6783 126.595 55.5376 125.148L55.5376 125.148L55.5477 125.144C59.5516 123.542 63.0052 121.456 65.9019 118.881L65.5697 118.507Z" />
              <use href="#b56e9dab-6ccb-4d32-ad02-6b4bb5d9bbeb" x="86" />
            </svg>
            <blockquote class="text-lg leading-8 sm:text-2xl sm:leading-9">
              <p>
                Starting a blog has been the most life-changing experience I've ever done! <br />
                All these good things would simply not have been possible
                without the simplicity and sustainability of Markdown.
              </p>
            </blockquote>
            <figcaption class="mt-8 text-base">
              <div class="hover:underline">
                <a href="https://kerkour.com" target="_blank" rel="noopener">Sylvain Kerkour</a>
              </div>
              <div class="mt-1 text-neutral-500">
                Blogging about programming and security since 2013, author of <a href="https://kerkour.com/black-hat-rust" target="_blank" rel="noopener" class="underline">Black Hat Rust</a>
              </div>
            </figcaption>
          </figure>
        </div>
      </div>
    </div> -->
    <div class="mx-auto max-w-7xl px-6 lg:px-8">
      <div class="mx-auto max-w-2xl text-center">
        <h2 class="mt-2 text-5xl font-semibold tracking-tight">
          In Markdown They Trust
        </h2>
      </div>
      <div class="mx-auto mt-12 grid max-w-2xl grid-cols-1 grid-rows-1 gap-8 text-sm/6  sm:grid-cols-2 xl:mx-0 xl:max-w-none xl:grid-flow-col xl:grid-cols-4">
        <figure class="rounded-2xl shadow-lg ring-1 ring-gray-900/5 sm:col-span-2 xl:col-start-2 xl:row-end-1">
          <blockquote class="p-6 text-lg font-medium tracking-tight sm:p-12 sm:text-xl/8">
            <p>{{ `“${featuredTestimonial.body}”` }}</p>
          </blockquote>
          <figcaption class="flex flex-wrap items-center gap-x-4 border-gray-900/10 px-6 py-4 sm:flex-nowrap">
            <img class="size-10 flex-none rounded-full bg-gray-50" :src="featuredTestimonial.author.imageUrl" alt="" />
            <div class="flex-auto">
              <div class="font-medium">{{ featuredTestimonial.author.name }}</div>
              <a v-if="featuredTestimonial.website" :href="featuredTestimonial.website.url" target="_blank" class="text-gray-600 hover:underline">
                {{ featuredTestimonial.website.name }}
              </a>
              <!-- <div class="text-gray-600">{{ `@${featuredTestimonial.author.handle}` }}</div> -->
            </div>
            <!-- <img class="h-10 w-auto flex-none" :src="featuredTestimonial.author.logoUrl" alt="" /> -->
          </figcaption>
        </figure>
        <div v-for="(columnGroup, columnGroupIdx) in testimonials" :key="columnGroupIdx" class="space-y-8 xl:contents xl:space-y-0">
          <div v-for="(column, columnIdx) in columnGroup" :key="columnIdx" :class="[(columnGroupIdx === 0 && columnIdx === 0) || (columnGroupIdx === testimonials.length - 1 && columnIdx === columnGroup.length - 1) ? 'xl:row-span-2' : 'xl:row-start-1', 'space-y-8']">
            <figure v-for="testimonial in column" class="rounded-2xl bg-white p-6 shadow-lg ring-1 ring-gray-900/5">
              <blockquote>
                <p>{{ `"${testimonial.body}"` }}</p>
              </blockquote>
              <figcaption class="mt-6 flex items-center gap-x-4">
                <img class="size-10 rounded-full bg-gray-50" :src="testimonial.author.imageUrl" alt="" />
                <div>
                  <div class="font-medium">{{ testimonial.author.name }}</div>
                  <!-- <a v-if="testimonial.website" :href="testimonial.website.url" target="_blank" class="text-gray-600 hover:underline">
                    {{ testimonial.website.name }}
                  </a> -->
                </div>
              </figcaption>
            </figure>
          </div>
        </div>
      </div>
    </div>
</template>

<script lang="ts" setup>
// props

// events

// composables

// lifecycle

// variables


const topQuotes = [
  'There is nothing permanent except Markdown.',
  // 'Markdown is the most powerful weapon which you can use to change the world.',
  'Small minds discuss people; average minds discuss events; great minds write Markdown.'
];

const featuredTestimonial =
{
      // body: ,
      body: topQuotes[Math.floor(Math.random() * topQuotes.length)],
      website: {
        name: 'kerkour.com',
        url: 'https://kerkour.com',
      },
      author: {
        name: 'Sylvain Kerkour',
        imageUrl: '/webapp/about/sylvain_kerkour.jpg',
      },
    };
const testimonials = [


[
  [
    {
      body: 'The true measure of any society can be found in how it uses Markdown.',
      author: {
        name: 'Mahatma Gandhi',
        imageUrl: '/webapp/about/mahatma_gandhi.jpg',
      },
    },
    {
      body: `Your time is limited, so don't waste it using something else than Markdown.`,
      author: {
        name: 'Steve Jobs',
        imageUrl: '/webapp/about/steve_jobs.jpg',
      },
    },
  ],
  [
    {
      body: 'Small things done with great love and Markdown will change the world. ',
      author: {
        name: 'Mother Teresa',
        imageUrl: '/webapp/about/mother_teresa.jpg',
      },
    },
  ],
],
[
  [
    {
      body: `Two things are infinite: the universe and the power of Markdown; and I'm not sure about the universe.`,
      author: {
        name: 'Albert Einstein ',
        imageUrl: '/webapp/about/albert_einstein.jpg',
      },
    },
  ],
  [
    {
      body: 'Using Markdown is the beginning of all wisdom.',
      author: {
        name: 'Aristotle',
        imageUrl: '/webapp/about/aristotle.jpg',
      },
    },
    {
      body: 'You only live once, but if you use Markdown, once is enough.',
      author: {
        name: 'Mae West ',
        imageUrl: '/webapp/about/mae_west.jpg',
      },
    },
  ],

],
]

// computed

// watch

// functions
</script>
