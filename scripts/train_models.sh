#!/bin/bash
# ============================================
# Train Models Script - تدريب النماذج
# ============================================

set -e

echo "🧠 HunterMind - Training Models"
echo "================================"

# تفعيل البيئة الافتراضية
source venv/bin/activate

# إنشاء مجلد النماذج
mkdir -p models/rl
mkdir -p models/embeddings
mkdir -p models/classifiers

echo ""
echo "📊 Training Reinforcement Learning models..."

# تدريب DQN Agent
echo "  - Training DQN Agent..."
python -c "
import asyncio
from learning.reinforcement.dqn_agent import DQNAgent
from learning.reinforcement.rl_environment import RLEnvironment

async def train():
    env = RLEnvironment()
    agent = DQNAgent(state_size=64, action_size=10)
    await agent.initialize()
    
    for episode in range(100):
        state = await env.reset()
        total_reward = 0
        done = False
        
        while not done:
            action = await agent.act(state)
            step_result = await env.step(action)
            await agent.remember(state, action, step_result.reward, step_result.next_state, step_result.done)
            await agent.replay()
            state = step_result.next_state
            total_reward += step_result.reward
            done = step_result.done
        
        if episode % 10 == 0:
            print(f'Episode {episode}: Total Reward = {total_reward:.2f}')
    
    await agent.save('models/rl/dqn_agent.h5')
    print('✅ DQN Agent trained and saved')

asyncio.run(train())
"

echo ""
echo "📊 Training PPO Agent..."
python -c "
import asyncio
from learning.reinforcement.ppo_agent import PPOAgent
from learning.reinforcement.rl_environment import RLEnvironment

async def train():
    env = RLEnvironment()
    agent = PPOAgent(state_size=64, action_size=10)
    await agent.initialize()
    
    for episode in range(100):
        state = await env.reset()
        episode_reward = 0
        done = False
        
        while not done:
            action, log_prob = await agent.get_action(state)
            step_result = await env.step(action)
            value = await agent.get_value(state)
            await agent.remember(state, action, step_result.reward, step_result.done, log_prob, value)
            state = step_result.next_state
            episode_reward += step_result.reward
            done = step_result.done
        
        await agent.update()
        
        if episode % 10 == 0:
            print(f'Episode {episode}: Total Reward = {episode_reward:.2f}')
    
    await agent.save('models/rl/ppo_agent')
    print('✅ PPO Agent trained and saved')

asyncio.run(train())
"

echo ""
echo "✅ All models trained successfully!"
echo ""
echo "📁 Models saved to: models/"
echo "   - models/rl/dqn_agent.h5"
echo "   - models/rl/ppo_agent_actor.h5"
echo "   - models/rl/ppo_agent_critic.h5"
