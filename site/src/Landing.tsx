import { Layout } from "./Layout";
import { AnalyticsSection } from "./sections/AnalyticsSection";
import { ApproversSection } from "./sections/ApproversSection";
import { ComparisonSection } from "./sections/ComparisonSection";
import { CtaSection } from "./sections/CtaSection";
import { HeroSection } from "./sections/HeroSection";
import { HowItWorksSection } from "./sections/HowItWorksSection";
import { IntegrationsSection } from "./sections/IntegrationsSection";
import { ProblemSection } from "./sections/ProblemSection";
import { ProtocolDepthSection } from "./sections/ProtocolDepthSection";
import { RulesSection } from "./sections/RulesSection";

export function Landing() {
  return (
    <Layout>
      <HeroSection />
      <ProblemSection />

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
