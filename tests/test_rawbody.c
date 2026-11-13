#include <pthread.h>
#include <sched.h>
#include <semaphore.h>
#include <stdatomic.h>

#include "unity/unity.h"
#include "rawbody.h"

#define RACE_THREAD_COUNT             8
#define RACE_ROUNDS                   20000
#define RACE_RAW_BODY_THREAD_COUNT    3

static atomic_int g_insideCount;
static atomic_int g_maxInsideCount;
static atomic_int g_enteredCount;

typedef struct {
  pthread_t m_thread;
  sem_t     m_tried;
  sem_t     m_released;
  bool      m_hasEntered;
} Holder_t;

void setUp(void)
{
  atomic_store(&g_insideCount, 0);
  atomic_store(&g_maxInsideCount, 0);
  atomic_store(&g_enteredCount, 0);
}

void tearDown(void) { rawbody_leaveIfEntered(); }

static void* static_hold(void* arg)
{
  Holder_t* holder = arg;
  holder->m_hasEntered = rawbody_tryEnter();
  sem_post(&holder->m_tried);
  sem_wait(&holder->m_released);
  rawbody_leaveIfEntered();
  return NULL;
}

static bool static_startHolder(Holder_t* holder)
{
  TEST_ASSERT_EQUAL_INT(0, sem_init(&holder->m_tried, 0, 0));
  TEST_ASSERT_EQUAL_INT(0, sem_init(&holder->m_released, 0, 0));
  TEST_ASSERT_EQUAL_INT(0, pthread_create(&holder->m_thread, NULL, static_hold, holder));
  TEST_ASSERT_EQUAL_INT(0, sem_wait(&holder->m_tried));
  return holder->m_hasEntered;
}

static void static_stopHolder(Holder_t* holder)
{
  TEST_ASSERT_EQUAL_INT(0, sem_post(&holder->m_released));
  TEST_ASSERT_EQUAL_INT(0, pthread_join(holder->m_thread, NULL));
  sem_destroy(&holder->m_tried);
  sem_destroy(&holder->m_released);
}

void test_unset_count_lets_no_thread_enter(void)
{
  TEST_ASSERT_FALSE(rawbody_tryEnter());
}

void test_threads_enter_up_to_the_count(void)
{
  rawbody_setThreadCount(2);

  Holder_t first;
  Holder_t second;
  TEST_ASSERT_TRUE(static_startHolder(&first));
  TEST_ASSERT_TRUE(static_startHolder(&second));
  TEST_ASSERT_FALSE(rawbody_tryEnter());

  static_stopHolder(&first);
  static_stopHolder(&second);
  TEST_ASSERT_TRUE(rawbody_tryEnter());
  rawbody_leaveIfEntered();
}

void test_a_thread_that_did_not_enter_leaves_nothing(void)
{
  rawbody_setThreadCount(1);

  rawbody_leaveIfEntered();
  Holder_t holder;
  TEST_ASSERT_TRUE(static_startHolder(&holder));
  TEST_ASSERT_FALSE(rawbody_tryEnter());

  static_stopHolder(&holder);
}

void test_a_second_leave_gives_up_no_place(void)
{
  rawbody_setThreadCount(1);
  TEST_ASSERT_TRUE(rawbody_tryEnter());

  Holder_t refused;
  TEST_ASSERT_FALSE(static_startHolder(&refused));
  static_stopHolder(&refused);

  rawbody_leaveIfEntered();
  rawbody_leaveIfEntered();

  Holder_t entered;
  Holder_t refused_again;
  TEST_ASSERT_TRUE(static_startHolder(&entered));
  TEST_ASSERT_FALSE(static_startHolder(&refused_again));
  static_stopHolder(&refused_again);
  static_stopHolder(&entered);
}

void test_count_0_lets_no_thread_enter(void)
{
  rawbody_setThreadCount(0);

  TEST_ASSERT_FALSE(rawbody_tryEnter());
}

void test_lowered_count_keeps_the_threads_inside(void)
{
  rawbody_setThreadCount(2);
  Holder_t first;
  Holder_t second;
  TEST_ASSERT_TRUE(static_startHolder(&first));
  TEST_ASSERT_TRUE(static_startHolder(&second));
  rawbody_setThreadCount(1);
  TEST_ASSERT_FALSE(rawbody_tryEnter());

  static_stopHolder(&first);
  TEST_ASSERT_FALSE(rawbody_tryEnter());

  static_stopHolder(&second);
  TEST_ASSERT_TRUE(rawbody_tryEnter());
  rawbody_leaveIfEntered();
}

static void* static_raceToEnter(void* arg)
{
  (void)arg;
  for (int round = 0; round < RACE_ROUNDS; round++)
  {
    if (!rawbody_tryEnter())
      continue;

    atomic_fetch_add(&g_enteredCount, 1);
    int inside_count = atomic_fetch_add(&g_insideCount, 1) + 1;
    int max_inside_count = atomic_load(&g_maxInsideCount);
    while (inside_count > max_inside_count && !atomic_compare_exchange_weak(&g_maxInsideCount, &max_inside_count, inside_count))
      ;
    sched_yield();
    atomic_fetch_sub(&g_insideCount, 1);
    rawbody_leaveIfEntered();
  }
  return NULL;
}

void test_racing_threads_never_exceed_the_count(void)
{
  rawbody_setThreadCount(RACE_RAW_BODY_THREAD_COUNT);

  pthread_t threads[RACE_THREAD_COUNT];
  for (int i = 0; i < RACE_THREAD_COUNT; i++)
    TEST_ASSERT_EQUAL_INT(0, pthread_create(&threads[i], NULL, static_raceToEnter, NULL));
  for (int i = 0; i < RACE_THREAD_COUNT; i++)
    TEST_ASSERT_EQUAL_INT(0, pthread_join(threads[i], NULL));

  TEST_ASSERT_TRUE(atomic_load(&g_enteredCount) > 0);
  TEST_ASSERT_TRUE(atomic_load(&g_maxInsideCount) <= RACE_RAW_BODY_THREAD_COUNT);

  Holder_t holders[RACE_RAW_BODY_THREAD_COUNT];
  for (int i = 0; i < RACE_RAW_BODY_THREAD_COUNT; i++)
    TEST_ASSERT_TRUE(static_startHolder(&holders[i]));
  TEST_ASSERT_FALSE(rawbody_tryEnter());
  for (int i = 0; i < RACE_RAW_BODY_THREAD_COUNT; i++)
    static_stopHolder(&holders[i]);
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(8, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_unset_count_lets_no_thread_enter);
  RUN_TEST(test_threads_enter_up_to_the_count);
  RUN_TEST(test_a_thread_that_did_not_enter_leaves_nothing);
  RUN_TEST(test_a_second_leave_gives_up_no_place);
  RUN_TEST(test_count_0_lets_no_thread_enter);
  RUN_TEST(test_lowered_count_keeps_the_threads_inside);
  RUN_TEST(test_racing_threads_never_exceed_the_count);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
