# Deployment Context Models

class DeploymentContext:
    def __init__(self, name: str, version: str):
        self.name = name
        self.version = version

    def __repr__(self):
        return f"<DeploymentContext name={self.name} version={self.version}>",

class Deployment:
    def __init__(self, context: DeploymentContext, status: str):
        self.context = context
        self.status = status

    def __repr__(self):
        return f"<Deployment context={self.context} status={self.status}>",

# Example Usage
if __name__ == '__main__':
    context = DeploymentContext('production', '1.0.0')
    deployment = Deployment(context, 'success')
    print(deployment)
