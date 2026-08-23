import { App, Tags } from 'aws-cdk-lib';
import { deploymentConfigFromContext } from './config';
import { ClavisStack } from './stack';

const app = new App();
const config = deploymentConfigFromContext(app.node);
const stack = new ClavisStack(app, `clv-${config.environmentName}`, config);
Tags.of(stack).add('application', 'clavis');
Tags.of(stack).add('managed-by', 'aws-cdk');
Tags.of(stack).add('environment', config.environmentName);
