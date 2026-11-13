#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>

#include "unity/unity.h"
#include "upstream.h"

#define RACE_THREAD_COUNT           8
#define RACE_ROUNDS                 20000
#define RACE_UPSTREAM_THREAD_COUNT  3

static atomic_int g_insideCount;
static atomic_int g_maxInsideCount;
static atomic_int g_enteredCount;

void setUp(void)
{
  atomic_store(&g_insideCount, 0);
  atomic_store(&g_maxInsideCount, 0);
  atomic_store(&g_enteredCount, 0);
}

void tearDown(void) {}

static int static_enter(int count)
{
  int entered = 0;
  for (int i = 0; i < count; i++)
  {
    if (upstream_tryEnter())
      entered++;
  }
  return entered;
}

static void static_leave(int count)
{
  for (int i = 0; i < count; i++)
    upstream_leave();
}

void test_unset_count_lets_no_thread_enter(void)
{
  TEST_ASSERT_FALSE(upstream_tryEnter());
}

void test_threads_enter_up_to_the_count(void)
{
  upstream_setThreadCount(3);

  TEST_ASSERT_EQUAL_INT(3, static_enter(3));
  TEST_ASSERT_FALSE(upstream_tryEnter());

  static_leave(3);
}

void test_thread_enters_again_once_one_leaves(void)
{
  upstream_setThreadCount(1);
  TEST_ASSERT_TRUE(upstream_tryEnter());
  TEST_ASSERT_FALSE(upstream_tryEnter());

  upstream_leave();
  TEST_ASSERT_TRUE(upstream_tryEnter());

  upstream_leave();
}

void test_count_0_lets_no_thread_enter(void)
{
  upstream_setThreadCount(0);

  TEST_ASSERT_FALSE(upstream_tryEnter());
}

void test_lowered_count_keeps_the_threads_inside(void)
{
  upstream_setThreadCount(2);
  TEST_ASSERT_EQUAL_INT(2, static_enter(2));
  upstream_setThreadCount(1);
  TEST_ASSERT_FALSE(upstream_tryEnter());

  upstream_leave();
  TEST_ASSERT_FALSE(upstream_tryEnter());

  upstream_leave();
  TEST_ASSERT_TRUE(upstream_tryEnter());

  upstream_leave();
}

static void* static_raceToEnter(void* arg)
{
  (void)arg;
  for (int round = 0; round < RACE_ROUNDS; round++)
  {
    if (!upstream_tryEnter())
      continue;

    atomic_fetch_add(&g_enteredCount, 1);
    int inside_count = atomic_fetch_add(&g_insideCount, 1) + 1;
    int max_inside_count = atomic_load(&g_maxInsideCount);
    while (inside_count > max_inside_count && !atomic_compare_exchange_weak(&g_maxInsideCount, &max_inside_count, inside_count))
      ;
    sched_yield();
    atomic_fetch_sub(&g_insideCount, 1);
    upstream_leave();
  }
  return NULL;
}

void test_racing_threads_never_exceed_the_count(void)
{
  upstream_setThreadCount(RACE_UPSTREAM_THREAD_COUNT);

  pthread_t threads[RACE_THREAD_COUNT];
  for (int i = 0; i < RACE_THREAD_COUNT; i++)
    TEST_ASSERT_EQUAL_INT(0, pthread_create(&threads[i], NULL, static_raceToEnter, NULL));
  for (int i = 0; i < RACE_THREAD_COUNT; i++)
    TEST_ASSERT_EQUAL_INT(0, pthread_join(threads[i], NULL));

  TEST_ASSERT_TRUE(atomic_load(&g_enteredCount) > 0);
  TEST_ASSERT_TRUE(atomic_load(&g_maxInsideCount) <= RACE_UPSTREAM_THREAD_COUNT);
  TEST_ASSERT_EQUAL_INT(RACE_UPSTREAM_THREAD_COUNT, static_enter(RACE_UPSTREAM_THREAD_COUNT + 1));
  static_leave(RACE_UPSTREAM_THREAD_COUNT);
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_unset_count_lets_no_thread_enter);
  RUN_TEST(test_threads_enter_up_to_the_count);
  RUN_TEST(test_thread_enters_again_once_one_leaves);
  RUN_TEST(test_count_0_lets_no_thread_enter);
  RUN_TEST(test_lowered_count_keeps_the_threads_inside);
  RUN_TEST(test_racing_threads_never_exceed_the_count);
  return UNITY_END();
}
