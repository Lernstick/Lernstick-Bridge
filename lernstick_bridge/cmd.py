import uvicorn

from lernstick_bridge.config import config

def main():
    uvicorn.run("lernstick_bridge.main:app", host=str(config.ip), port=config.port)

if __name__ == "__main__":
    main()