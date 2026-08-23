import { App, Tags } from 'aws-cdk-lib';
import { deploymentConfigFromContext } from './config';
import { HemligStack } from './stack';

const app = new App();
const config = deploymentConfigFromContext(app.node);
new HemligStack(app, `hml-${config.environmentName}`, config);
// Tag the whole app, not just this stack: consoleFqdn can make HemligStack create a
// sibling us-east-1 certificate stack, which would otherwise go untagged.
Tags.of(app).add('application', 'hemlig');
Tags.of(app).add('managed-by', 'aws-cdk');
Tags.of(app).add('environment', config.environmentName);
