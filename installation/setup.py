from setuptools import setup

setup(
    name='lernstick_bridge',
    version='0.1',
    packages=['lernstick_bridge', 'lernstick_bridge.db', 'lernstick_bridge.bridge', 'lernstick_bridge.schema',
              'lernstick_bridge.keylime', 'lernstick_bridge.routers'],
    url='',
    license='',
    author='Thore Sommer',
    author_email='mail@thson.de',
    description='Lernstick Keylime Bridge',
    entry_points={
        "console_scripts": [
            'lernstick_bridge=lernstick_bridge.cmd:main'
        ]
    }
)
