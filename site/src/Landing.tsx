import { Layout } from "./Layout";
import { HeroSection } from "./sections/HeroSection";
import { ProblemSection } from "./sections/ProblemSection";
import { ScrollDiagram } from "./components/ScrollDiagram";
import { ScrollDiagramSolution } from "./components/ScrollDiagramSolution";
import { RulesSection } from "./sections/RulesSection";
import { ApproversSection } from "./sections/ApproversSection";
import { ProtocolDepthSection } from "./sections/ProtocolDepthSection";
import { HowItWorksSection } from "./sections/HowItWorksSection";
import { AnalyticsSection } from "./sections/AnalyticsSection";
import { ComparisonSection } from "./sections/ComparisonSection";
import { IntegrationsSection } from "./sections/IntegrationsSection";
import { CtaSection } from "./sections/CtaSection";
import { Stripe } from "./components/Stripe";

export function Landing() {
  return (
    <Layout>
      <HeroSection />
      <ProblemSection />
      <Stripe />
      <ScrollDiagram />
      <ScrollDiagramSolution />
      <RulesSection />
      <ApproversSection />
      <ProtocolDepthSection />
      <HowItWorksSection />
      <AnalyticsSection />
      <ComparisonSection />
      <IntegrationsSection />
      <CtaSection />
    </Layout>
  );
}
