<template>
  <div class="mx-auto max-w-7xl px-6 lg:px-8">
    <div class="mx-auto max-w-4xl">
      <h2 class="text-2xl font-bold leading-10 tracking-tight text-gray-900">Frequently asked questions</h2>
      <p>
        Can't find the answer you're looking for? Reach out to our
        <RouterLink to="/contact" class="text-(--primary-color)">customer support</RouterLink>
        team.
      </p>
      <dl class="mt-10 space-y-6 divide-y divide-gray-900/10">
        <Disclosure as="div" v-for="faq in faqs" :key="faq.question" class="pt-6" v-slot="{ open }">
          <dt>
            <DisclosureButton class="flex w-full items-start justify-between text-left text-gray-900">
              <span class="text-base font-semibold leading-7">{{ faq.question }}</span>
              <span class="ml-6 flex h-7 items-center">
                <PlusSmallIcon v-if="!open" class="h-6 w-6" aria-hidden="true" />
                <MinusSmallIcon v-else class="h-6 w-6" aria-hidden="true" />
              </span>
            </DisclosureButton>
          </dt>
          <DisclosurePanel as="dd" class="mt-2 pr-12">
            <p class="text-base leading-7 text-gray-600">{{ faq.answer }}</p>
          </DisclosurePanel>
        </Disclosure>
      </dl>
    </div>
  </div>
</template>

<script lang="ts" setup>
import { Disclosure, DisclosureButton, DisclosurePanel } from '@headlessui/vue';
import { MinusSmallIcon, PlusSmallIcon } from '@heroicons/vue/24/outline';

type FaqItem =  {
  question: string;
  answer: string;
}

// props

// events

// composables

// lifecycle

// variables
const faqs: FaqItem[] = [
  {
    question: "Are there any transaction fees?",
    answer: `No. When you sell products on your Markdown Ninja websites you will only
      pay Stripe's standard fees. We don't believe that taking a cut is the right way to help businesses to grow.`,
  },
  {
    question: 'Will I be charged when my trial expires?',
    answer: `No. When your trial ends you'll be prompted to choose a paid plan to continue using Markdown Ninja.
    If you don't choose a plan, you won't be charged.`,
  },
  // {
  //   question: "What happens if I reach my emails quota?",
  //   answer: `You will be asked if you want to continue sending more emails. We charge $1 per 1000
  //     extra emails.`
  // },
  {
    question: 'Can I cancel at any time?',
    answer: `Yes. You can cancel at any point in the "billing" section of the app.`
      // Please note that we currently do not offer refunds on payments that have already been made.`,
  },
  // {
  //   question: "Is VAT included in plan prices?",
  //   answer:
  //     `VAT is not included in our plan prices. As most Markdown Ninja customers are businesses, they do not
  //     owe VAT and thus we charge the advertised flat price. VAT is still due for individuals and may
  //     be applied on all plan prices (ie. non-business entities).

  //     If you are an EU business, make sure you enter your EU VAT number to prove your business status
  //     and thus remove VAT from the price. If you are located outside the EU, we won't charge any VAT
  //     regardless of your business or consumer status.`,
  // },
  // {
  //   question: "Do you offer discounts on multiple Websites?",
  //   answer:
  //     `Yes! We offer discounts and consolidated billing if you are taking multiple Websites. Please contact our support team
  //     to see how we can help make the most of the Markdown Ninja platform.`,
  // },
];


// computed

// watch

// functions
</script>
