import { Layout } from "./Layout";
import { DotField } from "./components/DotField.tsx";
import { ShadeGradient } from "./components/ShadeBar.tsx";
import { ApproversSection } from "./sections/ApproversSection";
import { ComparisonSection } from "./sections/ComparisonSection";
import { CtaSection } from "./sections/CtaSection";
import { DemoSection } from "./sections/DemoSection";
import { DeploymentSection } from "./sections/DeploymentSection";
import { HeroSection } from "./sections/HeroSection";
import { ProblemSection } from "./sections/ProblemSection";
import { RulesSection } from "./sections/RulesSection";
import { TestSection } from "./sections/TestSection";
import { VpnSection } from "./sections/VpnSection";

export function Landing() {
  return (
    <Layout>
      <HeroSection />
      <VpnSection />
      <ShadeGradient color="text-navy" invert />
      <ProblemSection />
      <DemoSection />
      <ShadeGradient color="text-navy-700" />
      <RulesSection />
      <ShadeGradient color="text-navy" invert />
      <ApproversSection />
      <DotField class="text-canvas-400" />
      <TestSection />
      <DotField class="text-canvas-400" />
      <ComparisonSection />
      <DotField class="text-canvas-400" />
      <DeploymentSection />
      <DotField class="text-canvas-400" />
      <CtaSection />
    </Layout>
  );
}
